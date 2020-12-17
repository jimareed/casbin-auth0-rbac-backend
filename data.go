package main

import (
	"errors"
	"log"

	"github.com/casbin/casbin/v2"
)

/* Data type */
type Data struct {
	Id          int
	Name        string
	Description string
	Permissions string
}

var data = []Data{
	Data{Id: 1, Name: "data1", Description: "Data 1", Permissions: ""},
	Data{Id: 2, Name: "data2", Description: "Data 2", Permissions: ""},
	Data{Id: 3, Name: "data3", Description: "Data 3", Permissions: ""},
}

func readData(userEmail string) []Data {

	e, err := casbin.NewEnforcer("model.conf", "policy.csv")
	if err != nil {
		log.Fatalf("unable to create Casbin enforcer: %v", err)
	}

	filteredData := []Data{}

	for _, d := range data {
		d.Permissions = ""

		hasRead, err := e.Enforce(userEmail, d.Name, "read:data")
		if err != nil {
			log.Fatalf("Enforce error: %v", err)
		}
		hasWrite, err := e.Enforce(userEmail, d.Name, "write:data")
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

func updateData(userEmail string, name string, description string) error {
	e, err := casbin.NewEnforcer("model.conf", "policy.csv")
	if err != nil {
		log.Fatalf("unable to create Casbin enforcer: %v", err)
	}

	index := 0

	for _, d := range data {
		result, err := e.Enforce(userEmail, d.Name, "write:data")
		if err != nil {
			log.Fatalf("Enforce error: %v", err)
			return err
		}
		if result {
			if name == d.Name {
				data[index].Description = description
				return nil
			}
		}
		index++
	}

	return errors.New("data not found")
}
