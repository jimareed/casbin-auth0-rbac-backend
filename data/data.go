package data

import (
	"errors"
	"fmt"
	"log"

	"github.com/casbin/casbin/v2"
)

/* DataItem type */
type DataItem struct {
	Id          int
	Name        string
	Description string
	Permissions string
}

/* Data type */
type Data struct {
	enforcer *casbin.Enforcer
}

var nextId = 4

var dataItems = []DataItem{
	DataItem{Id: 1, Name: "data1", Description: "Data 1", Permissions: ""},
	DataItem{Id: 2, Name: "data2", Description: "Data 2", Permissions: ""},
	DataItem{Id: 3, Name: "data3", Description: "Data 3", Permissions: ""},
}

func Init(modelFile string, policyFile string) Data {
	d := Data{}

	e, err := casbin.NewEnforcer(modelFile, policyFile)
	if err != nil {
		log.Fatalf("unable to create Casbin enforcer: %v", err)
		return d
	}

	d.enforcer = e

	return d
}

func (data Data) ReadData(userEmail string) []DataItem {

	filteredData := []DataItem{}

	for _, d := range dataItems {
		d.Permissions = ""

		hasRead, err := data.enforcer.Enforce(userEmail, d.Name, "read:data")
		if err != nil {
			log.Fatalf("Enforce error: %v", err)
		}
		hasWrite, err := data.enforcer.Enforce(userEmail, d.Name, "write:data")
		if err != nil {
			log.Fatalf("Enforce error: %v", err)
		}
		if hasRead {
			d.Permissions = "read"

			if hasWrite {
				d.Permissions += " "
			}
		}
		if hasWrite {
			d.Permissions += "write"
		}

		if hasRead || hasWrite {
			filteredData = append(filteredData, d)
		}
	}

	return filteredData
}

func (data Data) NewData(userId string) (DataItem, error) {

	newData := DataItem{}

	newData.Id = nextId
	newData.Name = fmt.Sprintf("data%d", newData.Id)
	newData.Description = fmt.Sprintf("Data %d", newData.Id)

	_, err := data.enforcer.AddPolicy(userId, newData.Name, "write:data")
	if err != nil {
		log.Fatalf("error adding policy: %v", err)
		return newData, err
	}

	dataItems = append(dataItems, newData)
	nextId++

	return newData, nil
}

func (data Data) UpdateData(userId string, id int, description string) error {
	index := 0

	name := fmt.Sprintf("data%d", id)

	for _, d := range dataItems {
		result, err := data.enforcer.Enforce(userId, d.Name, "write:data")
		if err != nil {
			log.Fatalf("Enforce error: %v", err)
			return err
		}
		if result {
			if name == d.Name {
				dataItems[index].Description = description
				return nil
			}
		}
		index++
	}

	return errors.New("data not found")
}

func (data Data) DeleteData(userId string, id int) error {

	name := fmt.Sprintf("data%d", id)

	_, err := data.enforcer.RemovePolicy(userId, name, "write:data")
	if err != nil {
		log.Fatalf("error removing policy: %v", err)
		return err
	}

	for i, d := range dataItems {
		if d.Id == id {
			if i != len(dataItems)-1 {
				dataItems[i] = dataItems[len(dataItems)-1]
			}
			dataItems = dataItems[:len(dataItems)-1]
			return nil
		}
	}

	return errors.New("data not found")
}
