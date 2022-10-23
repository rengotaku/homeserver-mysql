package models

import "time"

type Packet struct {
	ID          uint      `gorm:"primaryKey"`
	LayerName   string    `gorm:"type:string;"`
	DstIP       string    `gorm:"type:string;"`
	DstPort     int       `gorm:"type:integer;"`
	Length      int       `gorm:"type:integer;"`
	EmergedTime int       `gorm:"type:integer;"`
	CreatedAt   time.Time `gorm:"index"`
}
