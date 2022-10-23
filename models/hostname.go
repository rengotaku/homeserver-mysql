package models

type Hostname struct {
	ID       uint    `gorm:"primaryKey"`
	IP       string  `gorm:"type:string;index:ip_uq,unique;"`
	Hostname *string `gorm:"type:string;"`
	ErrorFlg bool    `gorm:"type:bool;default:false;"`
}
