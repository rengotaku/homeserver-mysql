package models

import "time"

type Packet struct {
	ID         uint      `gorm:"primaryKey"`
	LayerName  string    `gorm:"type:string;"`
	PacketJson string    `gorm:"type:json;"`
	ErrorFlag  bool      `gorm:"type:bool;"`
	CreatedAt  time.Time `gorm:"index"`
}
