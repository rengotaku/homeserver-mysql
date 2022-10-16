package models

import (
	"fmt"

	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

const (
	location = "Asia%2FTokyo"
)

var (
	db *gorm.DB
)

type DbConfig struct {
	DbHost     string
	DbName     string
	DbUser     string
	DbPassword string
}

func Connection(config DbConfig) *gorm.DB {
	dsn := fmt.Sprintf("%s:%s@tcp(%s)/%s?charset=utf8mb4&parseTime=True&loc=%s", config.DbUser, config.DbPassword, config.DbHost, config.DbName, location)
	rawdb, err := gorm.Open(mysql.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Error),
	})
	if err != nil {
		fmt.Println("Error connecting to database:", err)
	}

	db = rawdb.Set("gorm:table_options", "ENGINE=InnoDB")

	return db
}
