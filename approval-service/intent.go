package main

import (
	"time"
)

type TransferIntent struct {
	OperationType      string    `json:"OperationType"`
	OperationID        string    `json:"OperationID"`
	Timestamp          time.Time `json:"Timestamp"`
	Asset              string    `json:"Asset"`
	TestNetwork        bool      `json:"TestNetwork"`
	Source             string    `json:"Source"`
	MasterKeyName      string    `json:"MasterKeyName"`
	DestinationType    string    `json:"DestinationType"`
	DestinationAmounts []struct {
		Destination   string `json:"Destination"`
		MasterKeyName string `json:"MasterKeyName"`
		Amount        string `json:"Amount"`
	} `json:"DestinationAmounts"`
	MaxFee string `json:"MaxFee"`
}

type CallContractIntent struct {
	OperationType   string    `json:"OperationType"`
	OperationID     string    `json:"OperationID"`
	Timestamp       time.Time `json:"Timestamp"`
	Call            string    `json:"Call"`
	Asset           string    `json:"Asset"`
	TestNetwork     bool      `json:"TestNetwork"`
	Source          string    `json:"Source"`
	MasterKeyName   string    `json:"MasterKeyName"`
	ContractAddress string    `json:"ContractAddress"`
	Amount          string    `json:"Amount"`
	MaxFee          string    `json:"MaxFee"`
}

type DeployContractIntent struct {
	OperationType string    `json:"OperationType"`
	OperationID   string    `json:"OperationID"`
	Timestamp     time.Time `json:"Timestamp"`
	ContractCode  string    `json:"ContractCode"`
	Asset         string    `json:"Asset"`
	TestNetwork   bool      `json:"TestNetwork"`
	Source        string    `json:"Source"`
	MasterKeyName string    `json:"MasterKeyName"`
	Amount        string    `json:"Amount"`
	MaxFee        string    `json:"MaxFee"`
}

type SignRawTransactionIntent struct {
	OperationType string    `json:"OperationType"`
	OperationID   string    `json:"OperationID"`
	Timestamp     time.Time `json:"Timestamp"`
	Asset         string    `json:"Asset"`
	TestNetwork   bool      `json:"TestNetwork"`
	Source        string    `json:"Source"`
	MasterKeyName string    `json:"MasterKeyName"`
	RawTransaction string   `json:"RawTransaction"`
}

type GenericIntent struct {
	OperationType  string `json:"OperationType"`
	Intent         []byte `json:"Intent"`
	IntentMetadata struct {
		RateInfo struct {
			Rate         float64 `json:"Rate"`
			FromCurrency string  `json:"FromCurrency"`
			ToCurrency   string  `json:"ToCurrency"`
		} `json:"RateInfo"`
	} `json:"IntentMetadata"`
	Initiator struct {
		UserName string `json:"UserName"`
		UserID   string `json:"UserID"`
	} `json:"Initiator"`
	Timestamp time.Time `json:"Timestamp"`
}
