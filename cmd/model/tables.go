package model

type Message struct {
	ID        uint32 `gorm:"id"`
	Devid     string `gorm:"devid"`
	Action    string `gorm:"action"`
	CreatedAt uint32 `gorm:"created_at"`
}

type StatisticsStatus struct {
	ID         uint32 `gorm:"id"`
	Devid      string `gorm:"devid"`
	Date       string `gorm:"date"`
	LastAction string `gorm:"last_action"`
	Offline    uint32 `gorm:"offline"`
	Online     uint32 `gorm:"online"`
}
