package main

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"log"
	"os"
	"strconv"
	"strings"
)

func writeProto(protoName string, fields map[int32]string, additional string, prefix string) {
	str := "syntax = \"proto3\";\n\n" + prefix + "message " + protoName + " {\n"
	for tag, typename := range fields {
		str += "  " + typename + " = " + strconv.Itoa(int(tag)) + ";\n"
	}
	if additional != "" {
		str += additional + "\n"
	}
	str += "}\n"

	logHeader := "------------ " + protoName + ".proto" + " ------------"
	log.Println(logHeader)
	log.Println(str)
	log.Println(strings.Repeat("-", len(logHeader)))

	err := os.MkdirAll("./out/", os.ModePerm)
	if err != nil {
		log.Println("Error creating directory in writeProto:", err)
	}
	file, err := os.Create("./out/" + protoName + ".proto")
	if err != nil {
		log.Println("Error creating file in writeProto:", err)
	}
	_, err = file.WriteString(str)
	if err != nil {
		log.Println("Error writing file in writeProto:", err)
	}
	err = file.Close()
	if err != nil {
		log.Println("Error closing file in writeProto:", err)
	}
}

func writePacketIds(packetIds map[uint16]string) {
	err := os.MkdirAll("./out/", os.ModePerm)
	if err != nil {
		log.Println("Error creating directory in writePacketIds:", err)
	}
	file, err := os.Create("./out/packetIds.json")
	if err != nil {
		log.Println("Error creating file in writePacketIds:", err)
	}
	jsonData, err := json.Marshal(packetIds)
	if err != nil {
		log.Println("Error marshaling to JSON in writePacketIds:", err)
		return
	}
	_, err = file.Write(jsonData)
	if err != nil {
		log.Println("Error writing to file in writePacketIds:", err)
		return
	}
	err = file.Close()
	if err != nil {
		log.Println("Error closing file in writePacketIds:", err)
	}
}

func unkGetPlayerTokenRsp(data []byte) (map[int32]uint64, error) {
	dMsg, err := parseUnkProto(data)
	if err != nil {
		log.Println("ParseUnkProto", err)
		return nil, err
	}
	var possibleServerSeeds = make(map[int32]uint64)
	// Get the unknown fields from the dynamic message
	unknownFieldTags := dMsg.GetUnknownFields()
	// Iterate over unknown fields
	for i := 0; i < len(unknownFieldTags); i++ {
		tag := unknownFieldTags[i]
		fields := dMsg.GetUnknownField(tag)
		if len(fields) > 1 {
			continue
		}
		field := fields[0]
		// Check if the field is of type bytes and has a length of 64
		var seed = make([]byte, base64.StdEncoding.DecodedLen(len(field.Contents)))
		n, err := base64.StdEncoding.Decode(seed, field.Contents)
		seed = seed[:n]
		if err == nil && n == 256 { // len(field.Contents) == 344 {
			seed, err = decrypt("data/private_key_5.pem", seed)
			if err != nil {
				continue
			}
			possibleServerSeed := binary.BigEndian.Uint64(seed)
			possibleServerSeeds[tag] = possibleServerSeed
			log.Println("Possible server seed", possibleServerSeed)
		}
	}
	if len(possibleServerSeeds) == 0 {
		return nil, errors.New("no possible server seed found")
	}
	log.Println("possibleServerSeeds:", possibleServerSeeds)
	return possibleServerSeeds, nil
}

func unkAchievementAllDataNotify(data []byte) error {
	errs := errors.New("not unkAchievementAllDataNotify")
	dMsg, err := parseUnkProto(data)
	if err != nil {
		log.Println("ParseUnkProto", err)
		return err
	}

	foundId := false
	foundTimestamp := false
	foundStatus := false
	var achievementListTag int32 = -1
	achievementFields := make(map[int32]string)

	unknownFieldTags := dMsg.GetUnknownFields()
	for i := 0; i < len(unknownFieldTags); i++ {
		tag := unknownFieldTags[i]
		fields := dMsg.GetUnknownField(tag)
		if len(fields) <= 1 || fields[0].Encoding != 2 {
			continue
		} else if len(achievementFields) > 0 {
			return errs
		}
		achievementFieldList := make(map[int32][]uint64)
		for _, field := range fields { // elements of achievement_list
			dMsg2, err := parseUnkProto(field.Contents)
			if err != nil {
				log.Println("ParseUnkProto", err)
				return err
			}
			unknownFieldTags2 := dMsg2.GetUnknownFields()
			if len(unknownFieldTags2) > 5 {
				return errs
			}
			for j := 0; j < len(unknownFieldTags2); j++ { // Fields of Achievement
				tag2 := unknownFieldTags2[j]
				fields2 := dMsg2.GetUnknownField(tag2)
				if len(fields2) > 1 {
					return errs
				}
				field2 := fields2[0]
				achievementFieldList[tag2] = append(achievementFieldList[tag2], field2.Value)
			}
		}

		// find fields
		for achievementTag, lst := range achievementFieldList {
			isTimestamp := lst[0] > 1420066800 // Wed Dec 31 2014 23:00:00 GMT+0000
			if isTimestamp {
				if foundTimestamp {
					return errs
				}
				achievementFields[achievementTag] = "uint32 finish_timestamp"
				foundTimestamp = true
				continue
			}
			canBeStatus := true
			isId := false
			for _, val := range lst {
				if val < 0 || val > 3 {
					canBeStatus = false
				}
				if val == 80014 { // Onward and Upward: Ascend a character to Phase 2 for the first time
					isId = true
					break
				}
			}
			if isId {
				if foundId {
					return errs
				}
				achievementFields[achievementTag] = "uint32 id"
				foundId = true
			} else if canBeStatus {
				if foundStatus {
					return errs
				}
				achievementFields[achievementTag] = "Status status"
				foundStatus = true
			}
		}
		if !foundStatus || !foundId || !foundTimestamp {
			continue
		}
		achievementListTag = tag
	}
	if !foundStatus || !foundId || !foundTimestamp {
		return errs
	}
	writeProto("Achievement", achievementFields, "  enum Status {\n    STATUS_INVALID = 0;\n    STATUS_UNFINISHED = 1;\n    STATUS_FINISHED = 2;\n    STATUS_REWARD_TAKEN = 3;\n  }", "")
	writeProto("AchievementAllDataNotify", map[int32]string{achievementListTag: "repeated Achievement achievement_list"}, "", "import \"Achievement.proto\";\n\n")
	return nil
}
