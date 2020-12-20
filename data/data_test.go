package data

import (
	"strings"
	"testing"
)

const checkMark = "\u2713"
const xMark = "\u2717"

const alice = "alice@example.com"

func TestReadData(t *testing.T) {

	t.Log("Alice:")

	data := Init("../model.conf", "../policy.csv")

	dataItems := data.ReadData("alice@example.com")

	if len(dataItems) == 2 {
		t.Log("Should have access to two data items.", checkMark)
	} else {
		t.Fatal("Should have access to two data items.", xMark)
	}
}

func TestNewData(t *testing.T) {

	t.Log("Alice:")

	data := Init("../model.conf", "../policy.csv")

	err := data.NewData(alice)

	if err == nil {
		t.Log("Should be able to create a new data item.", checkMark)
	} else {
		t.Fatal("Should be able to create a new data item.", xMark)
	}

	dataItems := data.ReadData(alice)

	if len(dataItems) == 3 {
		t.Log("Should have access to three data items.", checkMark)
	} else {
		t.Fatal("Should have access to three data items.", xMark, len(dataItems))
	}

}

func TestUpdateData(t *testing.T) {

	t.Log("Alice:")

	data := Init("../model.conf", "../policy.csv")

	dataItems := data.ReadData("alice@example.com")

	for _, d := range dataItems {
		if d.Name == "data1" {
			if d.Description == "Data 1" {
				t.Log("Should be able to lookup the description for data1 ", checkMark)
			} else {
				t.Fatal("Should have access to two data items.", xMark, d.Description)
			}
		}
	}

	err := data.UpdateData("alice@example.com", "data1", "Data 1 Updated")

	if err == nil {
		t.Log("Should be able to update the description for data1 ", checkMark)
	} else {
		t.Fatal("Should be able to update the description for data1.", xMark, err)
	}

	dataItems = data.ReadData("alice@example.com")

	for _, d := range dataItems {
		if d.Name == "data1" {
			if d.Description == "Data 1 Updated" {
				t.Log("Should be able to get the updated description for data1 ", checkMark)
			} else {
				t.Fatal("Should be able to get the updated description for data1.", xMark, d.Description)
			}
		}
	}

}

func TestPermissions(t *testing.T) {

	t.Log("Alice:")

	data := Init("../model.conf", "../policy.csv")

	dataItems := data.ReadData("alice@example.com")

	for _, d := range dataItems {
		if d.Name == "data1" {
			if strings.Contains(d.Permissions, "read") {
				t.Log("Should have read permissions for data1.", checkMark)
			} else {
				t.Fatal("Should have read permissions for data1.", xMark, d.Permissions)
			}
			if strings.Contains(d.Permissions, "write") {
				t.Log("Should have write permissions for data1.", checkMark)
			} else {
				t.Fatal("Should have write permissions for data1.", xMark, d.Permissions)
			}
		}
		if d.Name == "data2" {
			if strings.Contains(d.Permissions, "read") {
				t.Fatal("Should not have read permissions for data2.", xMark, d.Permissions)
			} else {
				t.Log("Should not have read permissions for data2.", checkMark)
			}
			if strings.Contains(d.Permissions, "write") {
				t.Log("Should have write permissions for data2.", checkMark)
			} else {
				t.Fatal("Should have write permissions for data2.", xMark, d.Permissions)
			}
		}
	}
}
