package repository

import (
	"github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

type Repository struct {
	DB          *gorm.DB
	MinIOClient *MinIOClient
}

func NewRepository(db *gorm.DB, minioClient *MinIOClient) *Repository {
	return &Repository{
		DB:          db,
		MinIOClient: minioClient,
	}
}

func (r *Repository) GetUserByEmail(email string) (*User, error) {
	var user User
	if err := r.DB.Where("email = ?", email).First(&user).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, nil
		}
		logrus.Error("Ошибка при получении пользователя:", err)
		return nil, err
	}
	return &user, nil
}

func (r *Repository) GetUserByID(id int) (*User, error) {
	var user User
	if err := r.DB.First(&user, id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, nil
		}
		logrus.Error("Ошибка при получении пользователя:", err)
		return nil, err
	}
	return &user, nil
}

func (r *Repository) GetAllCategories() ([]Category, error) {
	var categories []Category
	if err := r.DB.Find(&categories).Error; err != nil {
		logrus.Error("Ошибка при получении категорий:", err)
		return nil, err
	}
	return categories, nil
}

func (r *Repository) GetAllThreatTypes() ([]ThreatType, error) {
	var threatTypes []ThreatType
	if err := r.DB.Preload("Category").Find(&threatTypes).Error; err != nil {
		logrus.Error("Ошибка при получении типов угроз:", err)
		return nil, err
	}
	return threatTypes, nil
}

func (r *Repository) GetThreatTypeByID(id int) (*ThreatType, error) {
	var threatType ThreatType
	if err := r.DB.Preload("Category").First(&threatType, id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, nil
		}
		logrus.Error("Ошибка при получении типа угрозы:", err)
		return nil, err
	}
	return &threatType, nil
}

func (r *Repository) GetAllRequests() ([]Request, error) {
	var requests []Request
	if err := r.DB.Where("status != ?", "deleted").
		Preload("Creator").
		Preload("ThreatType.Category").
		Preload("RequestFacts").
		Find(&requests).Error; err != nil {
		logrus.Error("Ошибка при получении заявок:", err)
		return nil, err
	}
	return requests, nil
}

func (r *Repository) GetRequestByID(id int) (*Request, error) {
	var request Request
	if err := r.DB.Where("id = ? AND status != ?", id, "deleted").
		Preload("Creator").
		Preload("ThreatType.Category").
		Preload("RequestFacts").
		First(&request).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, nil
		}
		logrus.Error("Ошибка при получении заявки:", err)
		return nil, err
	}
	return &request, nil
}

func (r *Repository) CreateRequest(request *Request) error {
	if err := r.DB.Create(request).Error; err != nil {
		logrus.Error("Ошибка при создании заявки:", err)
		return err
	}
	return nil
}

func (r *Repository) GetDraftRequestByUserID(userID int) (*Request, error) {
	var request Request
	if err := r.DB.Where("creator_id = ? AND status = ?", userID, "draft").
		Preload("Creator").
		Preload("RequestFacts").
		Preload("RequestFacts").
		First(&request).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, nil
		}
		logrus.Error("Ошибка при получении черновика заявки:", err)
		return nil, err
	}
	return &request, nil
}

func (r *Repository) DeleteRequest(requestID int) error {
	if err := r.DB.Model(&Request{}).Where("id = ?", requestID).Update("status", "deleted").Error; err != nil {
		logrus.Error("Ошибка при удалении заявки:", err)
		return err
	}
	return nil
}

func (r *Repository) CreateFact(fact *Fact) error {
	var factCount int64
	if err := r.DB.Model(&Fact{}).Where("request_id = ?", fact.RequestID).Count(&factCount).Error; err != nil {
		logrus.Error("Ошибка при подсчете фактов заявки:", err)
		return err
	}

	if factCount == 0 {
		if err := r.UpdateRequestStatus(fact.RequestID, "awaiting"); err != nil {
			logrus.Error("Ошибка при обновлении статуса заявки на awaiting:", err)
			return err
		}
	}

	if err := r.DB.Create(fact).Error; err != nil {
		logrus.Error("Ошибка при создании факта:", err)
		return err
	}
	logrus.Info("Факт успешно создан. ID: ", fact.ID, ", RequestID: ", fact.RequestID)
	return nil
}

func (r *Repository) GetFactsByRequestID(requestID int) ([]Fact, error) {
	var facts []Fact
	if err := r.DB.Where("request_id = ?", requestID).
		Order("created_at ASC").
		Find(&facts).Error; err != nil {
		logrus.Error("Ошибка при получении фактов заявки:", err)
		return nil, err
	}
	logrus.Info("Найдено фактов для заявки ", requestID, ": ", len(facts))
	return facts, nil
}

func (r *Repository) UpdateRequestStatus(requestID int, status string) error {
	if err := r.DB.Model(&Request{}).Where("id = ?", requestID).Update("status", status).Error; err != nil {
		logrus.Error("Ошибка при обновлении статуса заявки:", err)
		return err
	}
	return nil
}
