package models

import (
	"fmt"
	"log"
	"os"
	"time"

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

func Connection(config DbConfig, debugFlg bool) *gorm.DB {
	dsn := fmt.Sprintf("%s:%s@tcp(%s)/%s?charset=utf8mb4&parseTime=True&loc=%s", config.DbUser, config.DbPassword, config.DbHost, config.DbName, location)
	var newLogr logger.Interface
	if debugFlg {
		newLogr = logger.New(
			log.New(os.Stdout, "\r\n", log.LstdFlags), // io writer
			logger.Config{
				SlowThreshold:             time.Second, // Slow SQL threshold
				LogLevel:                  logger.Info, // Log level
				IgnoreRecordNotFoundError: true,        // Ignore ErrRecordNotFound error for logger
				Colorful:                  false,       // Disable color
			},
		)
	} else {
		newLogr = logger.Default.LogMode(logger.Error)
	}

	rawdb, err := gorm.Open(mysql.Open(dsn), &gorm.Config{
		Logger: newLogr,
	})
	if err != nil {
		log.Panicln("Error connecting to database:", err)
	}

	db = rawdb.Set("gorm:table_options", "ENGINE=InnoDB")
	db = db.Session(&gorm.Session{CreateBatchSize: 1000})

	return db
}
