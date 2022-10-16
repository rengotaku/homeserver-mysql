package models

import "time"

type Packet struct {
	ID          uint `gorm:"primaryKey"`
	RawPacketID uint
	RawPacket   RawPacket `gorm:"association_autoupdate:false;association_autocreate:false"`
	LayerName   string    `gorm:"type:string;"`
	DstIP       *string   `gorm:"type:string;"`
	SrcIP       *string   `gorm:"type:string;"`
	DstMAC      *string   `gorm:"type:string;"`
	SrcMAC      *string   `gorm:"type:string;"`
	DstPort     *int      `gorm:"type:integer;"`
	SrcPort     *int      `gorm:"type:integer;"`
	Length      *int      `gorm:"type:integer;"`
	TTL         *int      `gorm:"type:integer;"`
	ErrorFlag   bool      `gorm:"type:bool;"`
	CreatedAt   time.Time `gorm:"index"`
}
