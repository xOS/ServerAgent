import hashlib
import os
import time

import requests
from github import Github
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

GITHUB_REPO = os.getenv("GITHUB_REPO", "xOS/ServerAgent")
GITEE_OWNER = os.getenv("GITEE_OWNER", "Ten")
GITEE_REPO = os.getenv("GITEE_REPO", "ServerAgent")

RETRYABLE_STATUS_CODES = (429, 500, 502, 503, 504)
MAX_ATTEMPTS = 5
API_TIMEOUT = (10, 60)
FILE_TIMEOUT = (15, 300)


def build_session():
    session = requests.Session()
    retry = Retry(
        total=5,
        connect=5,
        read=5,
        status=5,
        backoff_factor=1.5,
        status_forcelist=RETRYABLE_STATUS_CODES,
        allowed_methods=frozenset(["GET", "POST", "PUT", "PATCH", "DELETE"]),
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retry, pool_connections=10, pool_maxsize=10)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    session.headers.update({"Accept": "application/json"})
    return session


def retry_delay(attempt):
    return min(60, 2 ** attempt)


def robust_request(session, method, url, max_attempts=MAX_ATTEMPTS, **kwargs):
    last_error = None
    for attempt in range(1, max_attempts + 1):
        try:
            response = session.request(method, url, **kwargs)
            if response.status_code in RETRYABLE_STATUS_CODES and attempt < max_attempts:
                print(f"{method} {url} returned {response.status_code}, attempt {attempt}/{max_attempts}.")
                response.close()
                delay = retry_delay(attempt)
                print(f"Retrying in {delay}s...")
                time.sleep(delay)
                continue
            return response
        except (requests.Timeout, requests.ConnectionError) as err:
            last_error = err
            print(f"{method} {url} failed on attempt {attempt}/{max_attempts}: {err}")
            if attempt < max_attempts:
                delay = retry_delay(attempt)
                print(f"Retrying in {delay}s...")
                time.sleep(delay)
                continue
            raise

    if last_error is not None:
        raise last_error
    raise RuntimeError(f"{method} {url} failed unexpectedly.")


def parse_response_message(response):
    try:
        payload = response.json()
        if isinstance(payload, dict):
            return payload.get("message") or str(payload)
        return str(payload)
    except ValueError:
        return response.text.strip()


def download_asset(client, url, name):
    tmp_name = f"{name}.part"
    for attempt in range(1, MAX_ATTEMPTS + 1):
        try:
            with robust_request(
                client,
                "GET",
                url,
                timeout=FILE_TIMEOUT,
                stream=True,
                max_attempts=1,
            ) as response:
                response.raise_for_status()
                with open(tmp_name, "wb") as file_handle:
                    for chunk in response.iter_content(chunk_size=1024 * 1024):
                        if chunk:
                            file_handle.write(chunk)

            os.replace(tmp_name, name)
            print(f"Downloaded {name}")
            return get_abs_path(name)
        except requests.RequestException as err:
            print(f"Failed to download {name} on attempt {attempt}/{MAX_ATTEMPTS}: {err}")
            if attempt >= MAX_ATTEMPTS:
                raise
            delay = retry_delay(attempt)
            print(f"Retrying download in {delay}s...")
            time.sleep(delay)
        finally:
            if os.path.exists(tmp_name):
                try:
                    os.remove(tmp_name)
                except OSError:
                    pass


def get_github_latest_release():
    github_token = os.getenv("GITHUB_TOKEN")
    g = Github(github_token) if github_token else Github()
    repo = g.get_repo(GITHUB_REPO)
    release = repo.get_latest_release()
    if release:
        print(f"Latest release tag is: {release.tag_name}")
        print(f"Latest release info is: {release.body}")
        files = []
        download_client = build_session()
        try:
            for asset in release.get_assets():
                url = asset.browser_download_url
                name = asset.name
                files.append(download_asset(download_client, url, name))
        finally:
            download_client.close()

        print('Checking file integrities')
        checksum_path = get_abs_path("checksums.txt")
        if not os.path.exists(checksum_path):
            raise FileNotFoundError("checksums.txt not found in downloaded release assets")
        if not verify_checksum(checksum_path):
            raise RuntimeError("Checksum verification failed")
        sync_to_gitee(release.tag_name, release.body, files)
    else:
        print("No releases found.")


def find_gitee_release_id_by_tag(client, uri, token, tag):
    response = robust_request(
        client,
        "GET",
        uri,
        params={"access_token": token, "per_page": 100},
        timeout=API_TIMEOUT,
    )
    if response.status_code != 200:
        raise RuntimeError(
            f"List releases failed with status {response.status_code}: {parse_response_message(response)}"
        )

    for block in response.json():
        if block.get("tag_name") == tag:
            return block.get("id")
    return None


def delete_gitee_releases(latest_id, client, uri, token):
    response = robust_request(
        client,
        "GET",
        uri,
        params={"access_token": token, "per_page": 100},
        timeout=API_TIMEOUT,
    )
    if response.status_code != 200:
        raise ValueError(
            f"List releases failed with status {response.status_code}: {parse_response_message(response)}"
        )

    release_ids = [block.get("id") for block in response.json() if "id" in block]
    print(f"Current release ids: {release_ids}")

    for release_id in release_ids:
        if release_id == latest_id:
            continue

        release_uri = f"{uri}/{release_id}"
        delete_response = robust_request(
            client,
            "DELETE",
            release_uri,
            params={"access_token": token},
            timeout=API_TIMEOUT,
        )
        if delete_response.status_code == 204:
            print(f"Successfully deleted release #{release_id}.")
        elif delete_response.status_code == 404:
            print(f"Release #{release_id} already deleted.")
        else:
            raise ValueError(
                f"Delete release #{release_id} failed with status {delete_response.status_code}: "
                f"{parse_response_message(delete_response)}"
            )


def create_or_get_gitee_release_id(client, uri, token, tag, body):
    existing_release_id = find_gitee_release_id_by_tag(client, uri, token, tag)
    if existing_release_id:
        print(f"Found existing Gitee release for {tag}, id: {existing_release_id}")
        return existing_release_id

    release_data = {
        "access_token": token,
        "tag_name": tag,
        "name": tag,
        "body": body or "",
        "prerelease": "false",
        "target_commitish": "master",
    }
    response = robust_request(client, "POST", uri, data=release_data, timeout=API_TIMEOUT)
    if response.status_code == 201:
        release_info = response.json()
        return release_info.get("id")

    print(f"Create release failed with status {response.status_code}: {parse_response_message(response)}")

    # Some failures are caused by release already existing. Re-query once before aborting.
    existing_release_id = find_gitee_release_id_by_tag(client, uri, token, tag)
    if existing_release_id:
        print(f"Reuse existing Gitee release id: {existing_release_id}")
        return existing_release_id

    raise RuntimeError(
        f"Unable to create or locate Gitee release for tag {tag}: {parse_response_message(response)}"
    )


def upload_asset_to_gitee(client, asset_api_uri, token, file_path):
    file_name = os.path.basename(file_path)

    for attempt in range(1, MAX_ATTEMPTS + 1):
        try:
            with open(file_path, "rb") as file_handle:
                upload_response = robust_request(
                    client,
                    "POST",
                    asset_api_uri,
                    params={"access_token": token},
                    files={"file": (file_name, file_handle)},
                    timeout=FILE_TIMEOUT,
                    max_attempts=1,
                )

            if upload_response.status_code == 201:
                asset_info = upload_response.json()
                asset_name = asset_info.get("name", file_name)
                print(f"Successfully uploaded {asset_name}!")
                return

            message = parse_response_message(upload_response)
            lower_message = message.lower()
            if upload_response.status_code in (400, 409, 422) and (
                "already" in lower_message or "exists" in lower_message or "已存在" in message
            ):
                print(f"{file_name} already exists on Gitee, skip.")
                return

            print(
                f"Upload {file_name} failed on attempt {attempt}/{MAX_ATTEMPTS}, "
                f"status {upload_response.status_code}: {message}"
            )
        except requests.RequestException as err:
            print(f"Upload {file_name} failed on attempt {attempt}/{MAX_ATTEMPTS}: {err}")

        if attempt < MAX_ATTEMPTS:
            delay = retry_delay(attempt)
            print(f"Retrying upload of {file_name} in {delay}s...")
            time.sleep(delay)
            continue

        raise RuntimeError(f"Upload {file_name} failed after {MAX_ATTEMPTS} attempts")


def sync_to_gitee(tag: str, body: str, files):
    release_id = ""
    owner = GITEE_OWNER
    repo = GITEE_REPO
    release_api_uri = f"https://gitee.com/api/v5/repos/{owner}/{repo}/releases"
    api_client = build_session()

    access_token = os.getenv("GITEE_TOKEN")
    if not access_token:
        raise RuntimeError("GITEE_TOKEN is not set")

    release_id = create_or_get_gitee_release_id(api_client, release_api_uri, access_token, tag, body)
    if not release_id:
        raise RuntimeError("Failed to acquire a valid Gitee release id")

    print(f"Gitee release id: {release_id}")
    asset_api_uri = f"{release_api_uri}/{release_id}/attach_files"

    for file_path in files:
        upload_asset_to_gitee(api_client, asset_api_uri, access_token, file_path)

    # 仅保留最新 Release 以防超出 Gitee 仓库配额
    try:
        delete_gitee_releases(release_id, api_client,
                              release_api_uri, access_token)
    except ValueError as e:
        print(e)

    api_client.close()
    print("Sync is completed!")


def get_abs_path(path: str):
    wd = os.getcwd()
    return os.path.join(wd, path)


def compute_sha256(file: str):
    sha256_hash = hashlib.sha256()
    buf_size = 65536
    with open(file, 'rb') as f:
        while True:
            data = f.read(buf_size)
            if not data:
                break
            sha256_hash.update(data)
    return sha256_hash.hexdigest()


def verify_checksum(checksum_file: str):
    with open(checksum_file, 'r') as f:
        lines = f.readlines()

    all_ok = True

    for line in lines:
        parts = line.strip().split()
        if len(parts) < 2:
            continue

        checksum, file = parts[0], parts[1]
        abs_path = get_abs_path(file)
        computed_hash = compute_sha256(abs_path)

        if checksum == computed_hash:
            print(f"{file}: OK")
        else:
            print(f"{file}: FAIL (expected {checksum}, got {computed_hash})")
            all_ok = False

    return all_ok


if __name__ == "__main__":
    get_github_latest_release()
