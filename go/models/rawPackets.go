package models

type RawPacket struct {
	ID         uint   `gorm:"primaryKey"`
	PacketJson string `gorm:"type:json;"`
}
