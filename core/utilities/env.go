package utilities

import (
	"os"
	"strconv"
)

func GetEnv(key, defaultValue string) string {
	value, ok := os.LookupEnv(key)
	if ok {
		return value
	}
	os.Setenv(key, defaultValue)
	return defaultValue
}

func GetEnvInt(key string, defaultValue int) int {
	defaultValueString := strconv.Itoa(defaultValue)
	valueString := GetEnv(key, defaultValueString)
	value, err := strconv.Atoi(valueString)
	if err != nil {
		return defaultValue
	}
	return value
}

func GetEnvInt64(key string, defaultValue int64) int64 {
	defaultValueString := strconv.FormatInt(defaultValue, 10)
	valueString := GetEnv(key, defaultValueString)
	value, err := strconv.ParseInt(valueString, 10, 64)
	if err != nil {
		return defaultValue
	}
	return value
}

func GetEnvBool(key string, defaultValue bool) bool {
	defaultValueString := strconv.FormatBool(defaultValue)
	valueString := GetEnv(key, defaultValueString)
	value, err := strconv.ParseBool(valueString)
	if err != nil {
		return false
	}
	return value
}
