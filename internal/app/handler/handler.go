package handler

import (
	"net/http"
	"strconv"
	"threat-monitoring/internal/app/repository"

	"path/filepath"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

type Handler struct {
	Repository *repository.Repository
}

func NewHandler(r *repository.Repository) *Handler {
	return &Handler{
		Repository: r,
	}
}

// Главная страница для сотрудников
func (h *Handler) GetEmployeeIndex(ctx *gin.Context) {
	// Получаем все категории и типы угроз для формы создания заявки
	categories := h.Repository.Categories
	threatTypes := h.Repository.ThreatTypes

	ctx.HTML(http.StatusOK, "employee_index.html", gin.H{
		"categories":  categories,
		"threatTypes": threatTypes,
		"userType":    "employee",
	})
}

func (h *Handler) GetSpecialistIndex(ctx *gin.Context) {
	requests := h.Repository.Requests
	workers := h.Repository.Workers

	workerMap := make(map[int]repository.Worker)
	for _, worker := range workers {
		workerMap[worker.ID] = worker
	}

	ctx.HTML(http.StatusOK, "specialist_index.html", gin.H{
		"requests":  requests,
		"workerMap": workerMap,
		"userType":  "specialist",
	})
}

func (h *Handler) GetRequest(ctx *gin.Context) {
	idStr := ctx.Param("id")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		logrus.Error(err)
		ctx.HTML(http.StatusBadRequest, "error.html", gin.H{"error": "Неверный ID заявки"})
		return
	}

	var request repository.Request
	found := false
	for _, req := range h.Repository.Requests {
		if req.ID == id {
			request = req
			found = true
			break
		}
	}

	if !found {
		ctx.HTML(http.StatusNotFound, "error.html", gin.H{"error": "Заявка не найдена"})
		return
	}

	var worker repository.Worker
	for _, w := range h.Repository.Workers {
		if w.ID == request.WorkerID {
			worker = w
			break
		}
	}

	var threatType repository.ThreatType
	for _, t := range h.Repository.ThreatTypes {
		if t.ID == request.TypeID {
			threatType = t
			break
		}
	}

	var category repository.Category
	for _, c := range h.Repository.Categories {
		if c.ID == threatType.CategoryID {
			category = c
			break
		}
	}

	var targetFacts []repository.Fact
	for _, f := range h.Repository.Facts {
		if f.RequestID == id {
			targetFacts = append(targetFacts, f)
		}
	}

	ctx.HTML(http.StatusOK, "request.html", gin.H{
		"request":    request,
		"worker":     worker,
		"threatType": threatType,
		"facts":      targetFacts,
		"category":   category,
	})
}

func (h *Handler) GetThreat(ctx *gin.Context) {
	idStr := ctx.Param("id")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		logrus.Error(err)
		ctx.HTML(http.StatusBadRequest, "error.html", gin.H{"error": "Неверный ID угрозы"})
		return
	}

	var threatType repository.ThreatType
	found := false
	for _, t := range h.Repository.ThreatTypes {
		if t.ID == id {
			threatType = t
			found = true
			break
		}
	}

	if !found {
		ctx.HTML(http.StatusNotFound, "error.html", gin.H{"error": "Угроза не найдена"})
		return
	}

	var category repository.Category
	for _, c := range h.Repository.Categories {
		if c.ID == threatType.CategoryID {
			category = c
			break
		}
	}

	ctx.HTML(http.StatusOK, "threat.html", gin.H{
		"threatType": threatType,
		"category":   category,
	})
}

func (h *Handler) GetLogin(ctx *gin.Context) {
	ctx.HTML(http.StatusOK, "login.html", gin.H{})
}

func (h *Handler) HandleLogin(ctx *gin.Context) {
	userType := ctx.PostForm("user_type")
	email := ctx.PostForm("email")
	password := ctx.PostForm("password")

	if userType != "employee" && userType != "specialist" {
		ctx.HTML(http.StatusOK, "login.html", gin.H{"error": "Неверный тип пользователя"})
		return
	}

	if userType == "employee" {
		var user *repository.Worker
		for i := range h.Repository.Workers {
			if h.Repository.Workers[i].Email == email {
				user = &h.Repository.Workers[i]
				break
			}
		}
		if user == nil || user.Password != password {
			ctx.HTML(http.StatusOK, "login.html", gin.H{"error": "Неверный email или пароль"})
			return
		}
		ctx.Redirect(http.StatusFound, "/employee")
	} else {
		var user *repository.Specialist
		for i := range h.Repository.Specialists {
			if h.Repository.Specialists[i].Email == email {
				user = &h.Repository.Specialists[i]
				break
			}
		}
		if user == nil || user.Password != password {
			ctx.HTML(http.StatusOK, "login.html", gin.H{"error": "Неверный email или пароль"})
			return
		}
		ctx.Redirect(http.StatusFound, "/specialist")
	}
}

func getFileExtension(filename string) string {
	ext := strings.ToLower(filepath.Ext(filename))
	if ext == ".jpeg" {
		return ".jpg"
	}
	return ext
}
