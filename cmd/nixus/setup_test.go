package main

import "testing"

func TestSetupActivationDoneWithConfirmedRecord(t *testing.T) {
	useState(t)
	status := M{"setupComplete": true, "lastConfirmed": M{"id": "abc", "status": "confirmed"}, "settings": M{}}
	for _, raw := range list(setupProgress(status)["items"]) {
		item := obj(raw)
		if item["id"] == "activation" && item["done"] != true {
			t.Fatal("a confirmed generation record must complete the activation step")
		}
	}
	status["lastConfirmed"] = nil
	for _, raw := range list(setupProgress(status)["items"]) {
		if item := obj(raw); item["id"] == "activation" && item["done"] == true {
			t.Fatal("no confirmed generation must leave activation to do")
		}
	}
}
