package helpers

import "gorm.io/gorm"

func CleanupDB(db *gorm.DB) {
	db.Exec(`
		TRUNCATE TABLE
			facts,
			requests,
			users,
			threat_types,
			categories
		RESTART IDENTITY CASCADE
	`)
}
