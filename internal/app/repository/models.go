package repository

import "time"

type User struct {
	ID        int       `gorm:"primaryKey;autoIncrement" json:"id"`
	Email     string    `gorm:"uniqueIndex" json:"email"`
	Password  string    `json:"-"`
	FullName  string    `json:"full_name"`
	Phone     string    `json:"phone"`
	UserType  string    `json:"user_type"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type Category struct {
	ID       int    `gorm:"primaryKey;autoIncrement" json:"id"`
	Name     string `json:"name"`
	Priority int    `json:"priority"`
}

type ThreatType struct {
	ID         int       `gorm:"primaryKey;autoIncrement" json:"id"`
	CategoryID int       `json:"category_id"`
	Category   *Category `gorm:"foreignKey:CategoryID" json:"category"`
	Name       string    `json:"name"`
}

type Request struct {
	ID           int         `gorm:"primaryKey;autoIncrement" json:"id"`
	CreatorID    int         `json:"creator_id"`
	Creator      *User       `gorm:"foreignKey:CreatorID" json:"creator"`
	ModeratorID  *int        `json:"moderator_id"`
	Moderator    *User       `gorm:"foreignKey:ModeratorID" json:"moderator"`
	Title        string      `json:"title"`
	Description  string      `json:"description"`
	ThreatTypeID int         `json:"threat_type_id"`
	ThreatType   *ThreatType `gorm:"foreignKey:ThreatTypeID" json:"threat_type"`
	Status       string      `json:"status"`
	CreatedAt    time.Time   `json:"created_at"`
	RequestFacts []Fact      `gorm:"foreignKey:RequestID" json:"facts"`
	UpdatedAt    time.Time   `json:"updated_at"`
	ResultCount  int         `gorm:"-" json:"result_count,omitempty"`
	CompletedAt  *time.Time  `json:"completed_at"`
}

type Fact struct {
	ID            int       `gorm:"primaryKey;autoIncrement" json:"id"`
	RequestID     int       `json:"request_id"`
	Title         string    `json:"title"`
	Description   string    `json:"description"`
	ScreenshotURL string    `json:"screenshot_url"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

func (Category) TableName() string {
	return "categories"
}

func (ThreatType) TableName() string {
	return "threat_types"
}

func (Request) TableName() string {
	return "requests"
}

func (Fact) TableName() string {
	return "facts"
}
