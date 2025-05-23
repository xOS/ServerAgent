package fm

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"io/fs"
	"os"
	"os/user"
	"path/filepath"

	"github.com/xos/serveragent/pkg/util"
	pb "github.com/xos/serveragent/proto"
)

type Task struct {
	taskClient pb.ServerService_IOStreamClient
	printf     func(string, ...interface{})
	remoteData *pb.IOStreamData
}

func NewFMClient(client pb.ServerService_IOStreamClient, printFunc func(string, ...interface{})) *Task {
	return &Task{
		taskClient: client,
		printf:     printFunc,
	}
}

func (t *Task) DoTask(data *pb.IOStreamData) {
	t.remoteData = data

	switch t.remoteData.Data[0] {
	case 0:
		t.listDir()
	case 1:
		go t.download()
	case 2:
		t.upload()
	}
}

func (t *Task) listDir() {
	dir := string(t.remoteData.Data[1:])
	var entries []fs.DirEntry
	var err error
	for {
		entries, err = os.ReadDir(dir)
		if err != nil {
			usr, err := user.Current()
			if err != nil {
				t.taskClient.Send(&pb.IOStreamData{Data: CreateErr(err)})
				return
			}
			dir = usr.HomeDir + string(filepath.Separator)
			continue
		}
		break
	}
	var buffer bytes.Buffer
	td := Create(&buffer, dir)
	for _, e := range entries {
		newBin := AppendFileName(td, e.Name(), e.IsDir())
		td = newBin
	}
	t.taskClient.Send(&pb.IOStreamData{Data: td})
}

func (t *Task) download() {
	path := string(t.remoteData.Data[1:])
	file, err := os.Open(path)
	if err != nil {
		t.printf("Error opening file: %s", err)
		t.taskClient.Send(&pb.IOStreamData{Data: CreateErr(err)})
		return
	}
	defer file.Close()

	fileInfo, err := file.Stat()
	if err != nil {
		t.printf("Error getting file info: %s", err)
		t.taskClient.Send(&pb.IOStreamData{Data: CreateErr(err)})
		return
	}

	fileSize := fileInfo.Size()
	if fileSize <= 0 {
		t.taskClient.Send(&pb.IOStreamData{Data: CreateErr(errors.New("requested file is empty"))})
		return
	}

	// Send header (12 bytes)
	var header bytes.Buffer
	headerData := CreateFile(&header, uint64(fileSize))
	if err := t.taskClient.Send(&pb.IOStreamData{Data: headerData}); err != nil {
		t.printf("Error sending file header: %s", err)
		t.taskClient.Send(&pb.IOStreamData{Data: CreateErr(err)})
		return
	}

	buffer := make([]byte, util.FileBufferSize)
	for {
		n, err := file.Read(buffer)
		if err != nil {
			if err == io.EOF {
				return
			}
			t.printf("Error reading file: %s", err)
			t.taskClient.Send(&pb.IOStreamData{Data: CreateErr(err)})
			return
		}

		if err := t.taskClient.Send(&pb.IOStreamData{Data: buffer[:n]}); err != nil {
			t.printf("Error sending file chunk: %s", err)
			t.taskClient.Send(&pb.IOStreamData{Data: CreateErr(err)})
			return
		}
	}
}

func (t *Task) upload() {
	if len(t.remoteData.Data) < 9 {
		const err string = "data is invalid"
		t.printf(err)
		t.taskClient.Send(&pb.IOStreamData{Data: CreateErr(errors.New(err))})
		return
	}

	fileSize := binary.BigEndian.Uint64(t.remoteData.Data[1:9])
	path := string(t.remoteData.Data[9:])

	file, err := os.Create(path)
	if err != nil {
		t.printf("Error creating file: %s", err)
		t.taskClient.Send(&pb.IOStreamData{Data: CreateErr(err)})
		return
	}
	defer file.Close()

	totalReceived := uint64(0)

	t.printf("receiving file: %s, size: %d", file.Name(), fileSize)
	for totalReceived < fileSize {
		if t.remoteData, err = t.taskClient.Recv(); err != nil {
			t.printf("Error receiving data: %s", err)
			t.taskClient.Send(&pb.IOStreamData{Data: CreateErr(err)})
			return
		}

		bytesWritten, err := file.Write(t.remoteData.Data)
		if err != nil {
			t.printf("Error writing to file: %s", err)
			t.taskClient.Send(&pb.IOStreamData{Data: CreateErr(err)})
			return
		}

		totalReceived += uint64(bytesWritten)
	}
	t.printf("received file %s.", file.Name())
	t.taskClient.Send(&pb.IOStreamData{Data: completeIdentifier}) // NZUP
}
