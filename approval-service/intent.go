package main

import (
	"encoding/json"
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

type MakeTransactionIntent struct {
	OperationType string    `json:"OperationType"`
	OperationID   string    `json:"OperationID"`
	InitiatorID   string    `json:"InitiatorID"`
	InitiatorName string    `json:"InitiatorName"`
	Timestamp     time.Time `json:"Timestamp"`
	Asset         string    `json:"Asset"`
	TestNetwork   bool      `json:"TestNetwork"`
	Source        struct {
		MasterKeyName string `json:"MasterKeyName,omitempty"`
		AccountName   string `json:"AccountName,omitempty"`
		AddressIndex  *int   `json:"AddressIndex,omitempty"`
		Address       string `json:"Address,omitempty"`
	} `json:"Source"`
	Destination []struct {
		MasterKeyName string `json:"MasterKeyName,omitempty"`
		AccountName   string `json:"AccountName,omitempty"`
		AddressIndex  *int   `json:"AddressIndex,omitempty"`
		Address       string `json:"Address,omitempty"`
		Amount        string `json:"Amount"`
	} `json:"Destination"`
	RawTransaction string          `json:"RawTransaction,omitempty"`
	TxHash         string          `json:"TxHash,omitempty"`
	BlockchainSpec json.RawMessage `json:"BlockchainSpec,omitempty"`
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
