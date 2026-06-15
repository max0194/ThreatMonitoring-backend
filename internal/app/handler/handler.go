package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"threat-monitoring/internal/app/ds"
	"threat-monitoring/internal/app/pkg"
	"threat-monitoring/internal/app/repository"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"github.com/sirupsen/logrus"
)

const (
	accessTokenCookie = pkg.AccessTokenCookie
)

type Handler struct {
	Repository  *repository.Repository
	RedisClient *redis.Client
	jwtSecret   []byte
	jwtTTL      time.Duration
}

func NewHandler(r *repository.Repository, redisClient *redis.Client, jwtSecret []byte, jwtTTL time.Duration) *Handler {
	return &Handler{
		Repository:  r,
		RedisClient: redisClient,
		jwtSecret:   jwtSecret,
		jwtTTL:      jwtTTL,
	}
}

func (h *Handler) ReturnOK(ctx *gin.Context) {
	ctx.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func validatePhone(phone string) bool {
	re := regexp.MustCompile(`^\+7\d{10}$`)
	return re.MatchString(phone)
}

func (h *Handler) getCurrentUserType(ctx *gin.Context) (string, error) {
	if userType, exists := ctx.Get("user_type"); exists {
		if t, ok := userType.(string); ok {
			return t, nil
		}
	}
	userType, err := ctx.Cookie("user_type")
	if err != nil {
		return "", err
	}
	return userType, nil
}

func (h *Handler) getCurrentUserID(ctx *gin.Context) (int, error) {
	if userID, exists := ctx.Get("user_id"); exists {
		if id, ok := userID.(int); ok {
			return id, nil
		}
	}
	userIDStr, err := ctx.Cookie("user_id")
	if err != nil {
		return 0, err
	}
	userID, err := strconv.Atoi(userIDStr)
	if err != nil {
		return 0, err
	}
	return userID, nil
}

func (h *Handler) storeSession(ctx context.Context, token string, value string) error {
	return h.RedisClient.Set(ctx, pkg.SessionKey(token), value, h.jwtTTL).Err()
}

func (h *Handler) deleteSession(ctx context.Context, token string) error {
	return h.RedisClient.Del(ctx, pkg.SessionKey(token)).Err()
}

func (h *Handler) AuthMiddleware() gin.HandlerFunc {
	return pkg.AuthMiddleware(h.RedisClient, h.jwtSecret)
}

func (h *Handler) writeSessionCookies(ctx *gin.Context, token string) {
	http.SetCookie(ctx.Writer, &http.Cookie{
		Name:   accessTokenCookie,
		Value:  token,
		Path:   "/",
		MaxAge: int(h.jwtTTL.Seconds()),

		HttpOnly: true,
		Secure:   true,

		SameSite: http.SameSiteNoneMode,
	})
}

func (h *Handler) clearSessionCookies(ctx *gin.Context) {

	cookies := []string{
		accessTokenCookie,
		"user_id",
		"user_type",
		"user_name",
	}

	for _, name := range cookies {
		http.SetCookie(ctx.Writer, &http.Cookie{
			Name:   name,
			Value:  "",
			Path:   "/",
			MaxAge: -1,

			HttpOnly: true,
			Secure:   true,

			SameSite: http.SameSiteNoneMode,
		})
	}
}
func (h *Handler) writeJSONError(ctx *gin.Context, status int, message string) {
	ctx.JSON(status, gin.H{"status": "error", "message": message})
}

func (h *Handler) parseDateParam(value string) (*time.Time, bool, error) {
	logrus.Tracef("parseDateParam: value=%q", value)
	if value == "" {
		return nil, false, nil
	}
	t, err := time.Parse("2006-01-02", value)
	if err != nil {
		logrus.Warnf("Invalid date value=%q: %v", value, err)
		return nil, false, nil
	}
	return &t, true, nil
}

// LoginAPI godoc
// @Summary Зайти за пользователя
// @Description Позволяет зайти за пользователя, используя его данные.
// @Tags auth
// @Accept json
// @Produce json
// @Param request body LoginAPIInput true "Данные для входа"
// @Success 200 {object} map[string]interface{} "Успешный вход"
// @Failure 400 {object} map[string]interface{} "Неверные данные"
// @Failure 401 {object} map[string]interface{} "Неверный email или пароль"
// @Failure 403 {object} map[string]interface{} "Неверный тип пользователя"
// @Failure 500 {object} map[string]interface{} "Ошибка сервера"
// @Router /api/auth/login [post]
func (h *Handler) LoginAPI(ctx *gin.Context) {
	var body struct {
		Email    string `json:"email" binding:"required,email"`
		Password string `json:"password" binding:"required"`
	}
	if err := ctx.ShouldBindJSON(&body); err != nil {
		logrus.Debugf("LoginAPI: ошибка - неверные данные %v", err)
		h.writeJSONError(ctx, http.StatusBadRequest, "Неверные данные для входа")
		return
	}

	logrus.Debugf("LoginAPI: попытка входа: email=%s", body.Email)
	user, err := h.Repository.GetUserByEmail(body.Email)
	if err != nil || user == nil || user.Password != body.Password {
		logrus.Warnf("LoginAPI: ошибка аутентификации email=%s", body.Email)
		h.writeJSONError(ctx, http.StatusUnauthorized, "Неверный email или пароль")
		return
	}

	token, err := ds.CreateToken(h.jwtSecret, h.jwtTTL, user.ID, user.UserType, user.FullName)
	if err != nil {
		logrus.Error("LoginAPI: ошибка генерации токена", err)
		h.writeJSONError(ctx, http.StatusInternalServerError, "Ошибка генерации токена")
		return
	}

	if err := h.storeSession(ctx.Request.Context(), token, strconv.Itoa(user.ID)+"|"+user.UserType); err != nil {
		logrus.Error("LoginAPI: ошибка сохранения сессии", err)
		h.writeJSONError(ctx, http.StatusInternalServerError, "Ошибка сохранения сессии")
		return
	}

	http.SetCookie(ctx.Writer, &http.Cookie{
		Name:   "user_id",
		Value:  strconv.Itoa(user.ID),
		Path:   "/",
		MaxAge: int(h.jwtTTL.Seconds()),

		HttpOnly: true,
		Secure:   true,

		SameSite: http.SameSiteNoneMode,
	})
	http.SetCookie(ctx.Writer, &http.Cookie{
		Name:     "user_type",
		Value:    user.UserType,
		Path:     "/",
		MaxAge:   int(h.jwtTTL.Seconds()),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteNoneMode,
	})

	http.SetCookie(ctx.Writer, &http.Cookie{
		Name:     "user_name",
		Value:    user.FullName,
		Path:     "/",
		MaxAge:   int(h.jwtTTL.Seconds()),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteNoneMode,
	})
	h.writeSessionCookies(ctx, token)
	logrus.WithFields(logrus.Fields{"user_id": user.ID, "email": user.Email, "user_type": user.UserType}).Info("LoginAPI: пользователь авторизовался")
	ctx.JSON(http.StatusOK, gin.H{"status": "ok", "token": token, "user": user})

	pkg.IncrementLoginSuccess()
}

type RegisterAPIInput struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required"`
	FullName string `json:"full_name" binding:"required"`
	Phone    string `json:"phone" binding:"required"`
	UserType string `json:"user_type" binding:"required"`
}

// RegisterAPI godoc
// @Summary Зарегистрировать пользователя
// @Description Позволяет зарегистрировать пользователя. Необходим вход за специалиста.
// @Tags auth
// @Accept json
// @Produce json
// @Security ApiKeyAuth
// @Param request body RegisterAPIInput true "Данные для регистрации"
// @Success 200 {object} map[string]interface{} "Успешная регистрация"
// @Failure 400 {object} map[string]interface{} "Неверные данные"
// @Failure 403 {object} map[string]interface{} "Неверный тип пользователя"
// @Failure 500 {object} map[string]interface{} "Ошибка сервера"
// @Router /api/auth/register [post]
func (h *Handler) RegisterAPI(ctx *gin.Context) {
	userType, err := h.getCurrentUserType(ctx)
	if err != nil || userType != "specialist" {
		logrus.Warnf("RegisterAPI: ошибка типа пользователя или авторизации %v", err)
		h.writeJSONError(ctx, http.StatusBadRequest, "Ошибка типа пользователя или авторизации")
		return
	}
	var body struct {
		Email    string `json:"email" binding:"required,email"`
		Password string `json:"password" binding:"required"`
		FullName string `json:"full_name" binding:"required"`
		Phone    string `json:"phone" binding:"required"`
		UserType string `json:"user_type" binding:"required,oneof=employee specialist"`
	}
	if err := ctx.ShouldBindJSON(&body); err != nil {
		logrus.Debugf("RegisterAPI: неверные данные %v", err)
		h.writeJSONError(ctx, http.StatusBadRequest, "Неверные данные для регистрации")
		return
	}

	logrus.Debugf("RegisterAPI: попытка email=%s user_type=%s", body.Email, body.UserType)
	if !strings.HasSuffix(body.Email, "@company.com") {
		logrus.Warnf("RegisterAPI: ошибка домена (не @company.com) %v", err)
		h.writeJSONError(ctx, http.StatusBadRequest, "Разрешены только корпоративные email с доменом @company.com")
		return
	} else if !validatePhone(body.Phone) {
		logrus.Warnf("RegisterAPI: ошибка формата телефона %v", err)
		h.writeJSONError(ctx, http.StatusBadRequest, "Неверный формат телефона")
		return
	}

	existingUser, err := h.Repository.GetUserByEmail(body.Email)
	if err != nil {
		logrus.Warnf("RegisterAPI: ошибка проверки Email %v", err)
		h.writeJSONError(ctx, http.StatusInternalServerError, "Ошибка при проверке пользователя")
		return
	}
	if existingUser != nil {
		logrus.Warnf("RegisterAPI: уже существует пользователь с таким email=%s", body.Email)
		h.writeJSONError(ctx, http.StatusConflict, "Пользователь с таким email уже существует")
		return
	}

	user := &repository.User{
		Email:    strings.TrimSpace(body.Email),
		Password: strings.TrimSpace(body.Password),
		FullName: strings.TrimSpace(body.FullName),
		Phone:    strings.TrimSpace(body.Phone),
		UserType: body.UserType,
	}

	if err := h.Repository.CreateUser(user); err != nil {
		h.writeJSONError(ctx, http.StatusInternalServerError, "Ошибка при создании пользователя")
		return
	}
	logrus.WithFields(logrus.Fields{"user_email": user.Email, "user_type": user.UserType}).Info("Новый пользователь зарегистрирован")
	ctx.JSON(http.StatusCreated, gin.H{"status": "ok", "user": user})
}

// LogoutAPI godoc
// @Summary Выход из системы
// @Description Завершает текущую авторизованную сессию.
// @Tags auth
// @Accept json
// @Produce json
// @Security ApiKeyAuth
// @Success 200 {object} map[string]interface{}
// @Failure 401 {object} map[string]interface{}
// @Router /api/auth/logout [post]
func (h *Handler) LogoutAPI(ctx *gin.Context) {
	tokenString := pkg.TokenFromRequest(ctx)
	if tokenString == "" {
		logrus.Warn("LogoutAPI: требуется вход")
		h.writeJSONError(ctx, http.StatusUnauthorized, "Требуется вход")
		return
	}

	if err := h.deleteSession(ctx.Request.Context(), tokenString); err != nil {
		logrus.Warn("LogoutAPI: ошибка выхода")
		h.writeJSONError(ctx, http.StatusInternalServerError, "Ошибка выхода")
		return
	}

	if err := pkg.AddToBlacklist(
		ctx.Request.Context(),
		h.RedisClient,
		tokenString,
		h.jwtTTL,
	); err != nil {
		logrus.Warn("LogoutAPI: ошибка добавления токена в Blacklist")
		h.writeJSONError(ctx, http.StatusInternalServerError, "Ошибка добавления токена в Blacklist")
		return
	}

	h.clearSessionCookies(ctx)
	ctx.JSON(http.StatusOK, gin.H{"status": "ok"})
}

type CreateRequestInput struct {
	Title        string `json:"title" binding:"required"`
	Description  string `json:"description" binding:"required"`
	ThreatTypeID int    `json:"threat_type_id" binding:"required"`
}

// CreateRequestAPI godoc
// @Summary Создать заявку
// @Description Создает новую заявку для авторизованного пользователя.
// @Tags requests
// @Accept json
// @Produce json
// @Security ApiKeyAuth
// @Param request body CreateRequestInput true "Данные заявки"
// @Success 201 {object} map[string]interface{}
// @Failure 400 {object} map[string]interface{}
// @Failure 401 {object} map[string]interface{}
// @Failure 500 {object} map[string]interface{} "Ошибка при создании заявки"
// @Router /api/requests [post]
func (h *Handler) CreateRequestAPI(ctx *gin.Context) {
	userID, err := h.getCurrentUserID(ctx)
	if err != nil {
		logrus.Warn("CreateRequestAPI: требуется вход")
		h.writeJSONError(ctx, http.StatusUnauthorized, "Требуется вход")
		return
	}
	userType, err := h.getCurrentUserType(ctx)
	if err != nil {
		logrus.Warn("CreateRequestAPI: требуется вход")
		h.writeJSONError(ctx, http.StatusUnauthorized, "Требуется вход")
		return
	}

	keys := fmt.Sprintf(
		"requests:%s:%d",
		userType,
		userID,
	)
	var body struct {
		Title        string `json:"title" binding:"required"`
		Description  string `json:"description" binding:"required"`
		ThreatTypeID int    `json:"threat_type_id" binding:"required"`
	}
	if err := ctx.ShouldBindJSON(&body); err != nil {
		logrus.Warn("CreateRequestAPI: неверные данные для создания заявки")
		h.writeJSONError(ctx, http.StatusBadRequest, "Неверные данные для создания заявки")
		return
	}

	request := &repository.Request{
		Title:        strings.TrimSpace(body.Title),
		Description:  strings.TrimSpace(body.Description),
		ThreatTypeID: body.ThreatTypeID,
		CreatorID:    userID,
		Status:       "draft",
		CreatedAt:    time.Now(),
	}

	if err := h.Repository.CreateRequest(request); err != nil {
		logrus.Error("CreateRequestAPI: ошибка создания заявки")
		h.writeJSONError(ctx, http.StatusInternalServerError, "Ошибка при создании заявки")
		return
	}

	delkeys, err := h.RedisClient.Del(ctx, keys).Result()
	if err != nil {
		logrus.Error("ошибка удаления кэша:", err)
	} else {
		logrus.Infof("удалено ключей: %d", delkeys)
	}

	ctx.JSON(http.StatusCreated, gin.H{"status": "ok", "request": request})
}

// GetRequestsAPI godoc
// @Summary Получить список заявок
// @Description Возвращает список заявок. Доступно только после авторизации.
// @Tags requests
// @Accept json
// @Produce json
// @Security ApiKeyAuth
// @Param status query string false "Статус заявки"
// @Param date_from query string false "Дата от (YYYY-MM-DD)"
// @Param date_to query string false "Дата до (YYYY-MM-DD)"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]interface{} "Ошибка с параметрами запроса"
// @Failure 401 {object} map[string]interface{} "Требуется авторизация"
// @Failure 403 {object} map[string]interface{} "Доступ запрещён"
// @Failure 500 {object} map[string]interface{} "Внутренняя ошибка сервера"
// @Router /api/requests [get]
func (h *Handler) GetRequestsAPI(ctx *gin.Context) {
	userID, err := h.getCurrentUserID(ctx)
	if err != nil {
		logrus.Warn("GetRequestsAPI: требуется вход")
		h.writeJSONError(ctx, http.StatusUnauthorized, "Требуется вход")
		return
	}

	userType, err := h.getCurrentUserType(ctx)
	if err != nil {
		logrus.Error("GetRequestsAPI: ошибка при определении роли пользователя")
		h.writeJSONError(ctx, http.StatusInternalServerError, "Ошибка при определении роли пользователя")
		return
	}

	status := strings.TrimSpace(ctx.Query("status"))
	from, date_bool, err := h.parseDateParam(strings.TrimSpace(ctx.Query("date_from")))
	if err != nil && !date_bool {
		logrus.Warn("GetRequestsAPI: неверный формат даты date_from")
		h.writeJSONError(ctx, http.StatusBadRequest, "Неверный формат даты date_from")
		return
	}
	to, date_bool, err := h.parseDateParam(strings.TrimSpace(ctx.Query("date_to")))
	if err != nil && !date_bool {
		logrus.Warn("GetRequestsAPI: неверный формат даты date_to")
		h.writeJSONError(ctx, http.StatusBadRequest, "Неверный формат даты date_to")
		return
	}
	logrus.Tracef("GetRequestsAPI: фильтрация status=%q from=%v to=%v", status, from, to)

	key := fmt.Sprintf(
		"requests:%s:%d",
		userType,
		userID,
	)

	cached, err := h.RedisClient.Get(ctx, key).Result()
	if err == nil {
		logrus.Debug("GetRequestsAPI: cache hit")

		var requests []repository.Request
		if err := json.Unmarshal([]byte(cached), &requests); err == nil {

			ctx.JSON(http.StatusOK, gin.H{
				"status":   "ok",
				"count":    len(requests),
				"requests": requests,
			})
			return
		}
	} else {
		logrus.Debugf("GetRequestsAPI: cache miss для key=%s", key)
	}

	requests, err := h.Repository.GetRequests(status, from, to)
	if err != nil {
		logrus.Error("GetRequestsAPI: ошибка при получении заявок", err)
		h.writeJSONError(ctx, http.StatusInternalServerError, "Ошибка при получении заявок")
		return
	}

	if userType == "employee" {
		var filtered []repository.Request
		for _, req := range requests {
			if req.CreatorID == userID {
				filtered = append(filtered, req)
			}
		}
		requests = filtered
		logrus.Debugf("GetRequestsAPI: заявки отфильтрованы для %d: %d requests", userID, len(filtered))
	} else {
		var filtered []repository.Request
		for _, req := range requests {
			if req.Status != "draft" && req.Status != "closed" && req.Status != "rejected" && req.Status != "deleted" {
				filtered = append(filtered, req)
			}
		}
		requests = filtered
		logrus.Debugf("GetRequestsAPI: специалист %d видит заявок: %d", userID, len(filtered))
	}

	for idx := range requests {
		requests[idx].ResultCount = len(requests[idx].RequestFacts)
	}

	data, err := json.Marshal(requests)
	if err == nil {
		err = h.RedisClient.Set(
			ctx,
			key,
			data,
			120*time.Second,
		).Err()

		if err != nil {
			logrus.Warn("GetRequestsAPI: ошибка при установке кэша", err)
		}
	}

	ctx.JSON(http.StatusOK, gin.H{
		"status":   "ok",
		"count":    len(requests),
		"requests": requests,
	})
}

// GetRequestAPI godoc
// @Summary Получить заявку
// @Description Возвращает заявку по ID. Доступно только после авторизации.
// @Tags requests
// @Accept json
// @Produce json
// @Security ApiKeyAuth
// @Param id path int true "ID заявки"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]interface{} "Неверный ID заявки"
// @Failure 401 {object} map[string]interface{} "Требуется авторизация"
// @Failure 403 {object} map[string]interface{} "Доступ запрещён"
// @Failure 404 {object} map[string]interface{} "Заявка не найдена"
// @Router /api/requests/{id} [get]
func (h *Handler) GetRequestAPI(ctx *gin.Context) {
	userID, err := h.getCurrentUserID(ctx)
	if err != nil {
		logrus.Warnf("GetRequestAPI: требуется вход: %d", userID)
		h.writeJSONError(ctx, http.StatusUnauthorized, "Требуется вход")
		return
	}

	userType, err := h.getCurrentUserType(ctx)
	if err != nil {
		logrus.Errorf("GetRequestAPI: ошибка при определении роли пользователя: %d", userID)
		h.writeJSONError(ctx, http.StatusInternalServerError, "Ошибка при определении роли пользователя")
		return
	}

	idStr := ctx.Param("id")
	request_id, err := strconv.Atoi(idStr)
	if err != nil {
		logrus.Errorf("GetRequestAPI: неверный ID заявки: %d", request_id)
		h.writeJSONError(ctx, http.StatusBadRequest, "Неверный ID заявки")
		return
	}

	key := fmt.Sprintf(
		"request:%d:%s:%d",
		request_id,
		userType,
		userID,
	)

	cached, err := h.RedisClient.Get(ctx, key).Result()
	if err == nil {
		logrus.Debug("GetRequestAPI: cache hit")

		var request repository.Request
		if err := json.Unmarshal([]byte(cached), &request); err == nil {

			ctx.JSON(http.StatusOK, gin.H{
				"status":  "ok",
				"count":   1,
				"request": request,
			})
			return
		}
	} else {
		logrus.Debugf("GetRequestAPI: cache miss для key=%s", key)
	}

	request, err := h.Repository.GetRequestByID(request_id)
	if err != nil {
		logrus.Error("GetRequestAPI: ошибка получения заявки ", err)
		h.writeJSONError(ctx, http.StatusInternalServerError, "Ошибка при получении заявки")
		return
	}
	if request == nil {
		logrus.Error("GetRequestAPI: заявка не найдена: ", request)
		h.writeJSONError(ctx, http.StatusNotFound, "Заявка не найдена")
		return
	}

	if userType == "employee" && request.CreatorID != userID {
		logrus.Errorf("GetRequestAPI: доступ к заявке %d запрещён для %d", request.ID, userID)
		h.writeJSONError(ctx, http.StatusForbidden, "Доступ к этой заявке запрещён")
		return
	}

	request.ResultCount = len(request.RequestFacts)

	data, err := json.Marshal(request)
	if err == nil {
		err = h.RedisClient.Set(
			ctx,
			key,
			data,
			120*time.Second,
		).Err()

		if err != nil {
			logrus.Warn("GetRequestAPI: ошибка при установке кэша", err)
		}
	}

	ctx.JSON(http.StatusOK, gin.H{"status": "ok", "request": request})
}

// UpdateRequestAPI godoc
// @Summary Обновить заявку
// @Description Обновляет существующую заявку, если пользователь является её создателем.
// @Tags requests
// @Accept json
// @Produce json
// @Security ApiKeyAuth
// @Param id path int true "ID заявки"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]interface{}
// @Failure 401 {object} map[string]interface{}
// @Failure 403 {object} map[string]interface{}
// @Failure 404 {object} map[string]interface{}
// @Router /api/requests/{id} [put]
func (h *Handler) UpdateRequestAPI(ctx *gin.Context) {
	userID, err := h.getCurrentUserID(ctx)
	if err != nil {
		logrus.Warn("UpdateRequestAPI: требуется вход")
		h.writeJSONError(ctx, http.StatusUnauthorized, "Требуется вход")
		return
	}

	userType, err := h.getCurrentUserType(ctx)
	if err != nil || userType != "employee" {
		logrus.Warn("SubmitRequestAPI: только специалист может брать заявку: ", userType)
		h.writeJSONError(ctx, http.StatusForbidden, "Только специалист может брать заявку")
		return
	}

	idStr := ctx.Param("id")
	requestID, err := strconv.Atoi(idStr)
	if err != nil {
		logrus.Warn("UpdateRequestAPI: неверный ID заявки: ", requestID)
		h.writeJSONError(ctx, http.StatusBadRequest, "Неверный ID заявки")
		return
	}

	key := fmt.Sprintf(
		"request:%d:%s:%d",
		requestID,
		userType,
		userID,
	)

	keys := fmt.Sprintf(
		"requests:%s:%d",
		userType,
		userID,
	)

	request, err := h.Repository.GetRequestByID(requestID)
	if err != nil || request == nil {
		logrus.Warn("UpdateRequestAPI: заявка не найдена: ", request)
		h.writeJSONError(ctx, http.StatusNotFound, "Заявка не найдена")
		return
	}
	if request.CreatorID != userID {
		logrus.Warn("UpdateRequestAPI: только создатель может изменять заявку: ", request)
		h.writeJSONError(ctx, http.StatusForbidden, "Только создатель может изменять заявку")
		return
	}
	if request.Status != "draft" {
		logrus.Warn("UpdateRequestAPI: изменение заявки возможно только в статусе draft: ", request.Status)
		h.writeJSONError(ctx, http.StatusBadRequest, "Изменение заявки возможно только в статусе draft")
		return
	}

	var body struct {
		Title        string `json:"title"`
		Description  string `json:"description"`
		ThreatTypeID int    `json:"threat_type_id"`
	}
	if err := ctx.ShouldBindJSON(&body); err != nil {
		logrus.Warn("UpdateRequestAPI: неверные данные заявки ")
		h.writeJSONError(ctx, http.StatusBadRequest, "Неверные данные заявки")
		return
	}

	updates := map[string]interface{}{}
	if strings.TrimSpace(body.Title) != "" {
		updates["title"] = strings.TrimSpace(body.Title)
	}
	if strings.TrimSpace(body.Description) != "" {
		updates["description"] = strings.TrimSpace(body.Description)
	}
	if body.ThreatTypeID > 0 {
		updates["threat_type_id"] = body.ThreatTypeID
	}
	if len(updates) == 0 {
		logrus.Warn("UpdateRequestAPI: нет данных для обновления")
		h.writeJSONError(ctx, http.StatusBadRequest, "Нет данных для обновления")
		return
	}
	if err := h.Repository.UpdateRequest(requestID, updates); err != nil {
		logrus.Error("UpdateRequestAPI: ошибка при обновлении заявки")
		h.writeJSONError(ctx, http.StatusInternalServerError, "Ошибка при обновлении заявки")
		return
	}

	delkey, err := h.RedisClient.Del(ctx, key).Result()
	if err != nil {
		logrus.Error("ошибка удаления кэша:", err)
	} else {
		logrus.Infof("удалено ключей: %d", delkey)
	}
	delkeys, err := h.RedisClient.Del(ctx, keys).Result()
	if err != nil {
		logrus.Error("ошибка удаления кэша:", err)
	} else {
		logrus.Infof("удалено ключей: %d", delkeys)
	}

	ctx.JSON(http.StatusOK, gin.H{"status": "ok"})
}

// SubmitRequest godoc
// @Summary Взять заявку в работу
// @Description Специалист принимает заявку для обработки.
// @Tags requests
// @Accept json
// @Produce json
// @Security ApiKeyAuth
// @Param id path int true "ID заявки"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]interface{}
// @Failure 401 {object} map[string]interface{}
// @Failure 403 {object} map[string]interface{}
// @Failure 404 {object} map[string]interface{}
// @Router /api/requests/{id}/submit [put]
func (h *Handler) SubmitRequest(ctx *gin.Context) {
	userID, err := h.getCurrentUserID(ctx)
	if err != nil {
		logrus.Warn("SubmitRequestAPI: требуется вход")
		h.writeJSONError(ctx, http.StatusUnauthorized, "Требуется вход")
		return
	}
	userType, err := h.getCurrentUserType(ctx)
	if err != nil || userType != "specialist" {
		logrus.Warn("SubmitRequestAPI: только специалист может брать заявку: ", userType)
		h.writeJSONError(ctx, http.StatusForbidden, "Только специалист может брать заявку")
		return
	}

	idStr := ctx.Param("id")
	requestID, err := strconv.Atoi(idStr)
	if err != nil {
		logrus.Warn("SubmitRequestAPI: неверный ID заявки: ", requestID)
		h.writeJSONError(ctx, http.StatusBadRequest, "Неверный ID заявки")
		return
	}

	key := fmt.Sprintf(
		"request:%d:%s:%d",
		requestID,
		userType,
		userID,
	)

	keys := fmt.Sprintf(
		"requests:%s:%d",
		userType,
		userID,
	)

	request, err := h.Repository.GetRequestByID(requestID)
	if err != nil || request == nil {
		logrus.Warn("SubmitRequestAPI: заявка не найдена: ", request)
		h.writeJSONError(ctx, http.StatusNotFound, "Заявка не найдена")
		return
	}
	if request.Status != "awaiting" {
		logrus.Warn("SubmitRequestAPI: принятие заявки возможно только в статусе awaiting: ", request.Status)
		h.writeJSONError(ctx, http.StatusBadRequest, "Заявку можно принять только в статусе awaiting")
		return
	}

	updates := map[string]interface{}{
		"status":       "taken",
		"moderator_id": userID,
	}
	if err := h.Repository.UpdateRequest(requestID, updates); err != nil {
		logrus.Error("SubmitRequestAPI: ошибка при принятии заявки")
		h.writeJSONError(ctx, http.StatusInternalServerError, "Ошибка при принятии заявки")
		return
	}

	delkey, err := h.RedisClient.Del(ctx, key).Result()
	if err != nil {
		logrus.Error("ошибка удаления кэша:", err)
	} else {
		logrus.Infof("удалено ключей: %d", delkey)
	}
	delkeys, err := h.RedisClient.Del(ctx, keys).Result()
	if err != nil {
		logrus.Error("ошибка удаления кэша:", err)
	} else {
		logrus.Infof("удалено ключей: %d", delkeys)
	}

	ctx.JSON(http.StatusOK, gin.H{"status": "ok"})
}

// CompleteRequest godoc
// @Summary Завершить заявку
// @Description Специалист завершает заявку со статусом closed или rejected.
// @Tags requests
// @Accept json
// @Produce json
// @Security ApiKeyAuth
// @Param id path int true "ID заявки"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]interface{}
// @Failure 401 {object} map[string]interface{}
// @Failure 403 {object} map[string]interface{}
// @Failure 404 {object} map[string]interface{}
// @Router /api/requests/{id}/complete [put]
func (h *Handler) CompleteRequest(ctx *gin.Context) {
	userID, err := h.getCurrentUserID(ctx)
	if err != nil {
		logrus.Warn("CompleteRequest: требуется вход")
		h.writeJSONError(ctx, http.StatusUnauthorized, "Требуется вход")
		return
	}
	userType, err := h.getCurrentUserType(ctx)
	if err != nil || userType != "specialist" {
		logrus.Warn("CompleteRequest: только специалист может брать заявку: ", userType)
		h.writeJSONError(ctx, http.StatusForbidden, "Только специалист может завершать заявку")
		return
	}

	idStr := ctx.Param("id")
	requestID, err := strconv.Atoi(idStr)
	if err != nil {
		logrus.Warn("CompleteRequest: неверный ID заявки: ", requestID)
		h.writeJSONError(ctx, http.StatusBadRequest, "Неверный ID заявки")
		return
	}

	key := fmt.Sprintf(
		"request:%d:%s:%d",
		requestID,
		userType,
		userID,
	)

	keys := fmt.Sprintf(
		"requests:%s:%d",
		userType,
		userID,
	)

	request, err := h.Repository.GetRequestByID(requestID)
	if err != nil || request == nil {
		logrus.Warn("CompleteRequest: заявка не найдена: ", request)
		h.writeJSONError(ctx, http.StatusNotFound, "Заявка не найдена")
		return
	}
	if request.Status != "taken" {
		logrus.Warn("CompleteRequest: закрытие заявки возможно только в статусе taken: ", request.Status)
		h.writeJSONError(ctx, http.StatusBadRequest, "Заявку можно закрыть только в статусе taken")
		return
	}

	if err := h.Repository.CompleteRequest(requestID, userID, "closed"); err != nil {
		logrus.Warn("CompleteRequest: Ошибка завершения заявки: ", err)
		h.writeJSONError(ctx, http.StatusBadRequest, "Ошибка завершения заявки")
		return
	}

	delkey, err := h.RedisClient.Del(ctx, key).Result()
	if err != nil {
		logrus.Error("ошибка удаления кэша:", err)
	} else {
		logrus.Infof("удалено ключей: %d", delkey)
	}
	delkeys, err := h.RedisClient.Del(ctx, keys).Result()
	if err != nil {
		logrus.Error("ошибка удаления кэша:", err)
	} else {
		logrus.Infof("удалено ключей: %d", delkeys)
	}

	ctx.JSON(http.StatusOK, gin.H{"status": "ok"})
}

// DeleteRequestAPI godoc
// @Summary Удалить заявку
// @Description Удаляет заявку, если у пользователя есть право на это.
// @Tags requests
// @Accept json
// @Produce json
// @Security ApiKeyAuth
// @Param id path int true "ID заявки"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]interface{}
// @Failure 401 {object} map[string]interface{}
// @Failure 403 {object} map[string]interface{}
// @Failure 404 {object} map[string]interface{}
// @Router /api/requests/{id} [delete]
func (h *Handler) DeleteRequestAPI(ctx *gin.Context) {
	userID, err := h.getCurrentUserID(ctx)
	if err != nil {
		logrus.Warn("DeleteRequestAPI: требуется вход")
		h.writeJSONError(ctx, http.StatusUnauthorized, "Требуется вход")
		return
	}
	userType, _ := h.getCurrentUserType(ctx)

	idStr := ctx.Param("id")
	requestID, err := strconv.Atoi(idStr)
	if err != nil {
		logrus.Warn("DeleteRequestAPI: неверный ID заявки: ", requestID)
		h.writeJSONError(ctx, http.StatusBadRequest, "Неверный ID заявки")
		return
	}

	key := fmt.Sprintf(
		"request:%d:%s:%d",
		requestID,
		userType,
		userID,
	)

	keys := fmt.Sprintf(
		"requests:%s:%d",
		userType,
		userID,
	)

	request, err := h.Repository.GetRequestByID(requestID)
	if err != nil || request == nil {
		logrus.Warn("DeleteRequestAPI: заявка не найдена: ", request)
		h.writeJSONError(ctx, http.StatusNotFound, "Заявка не найдена")
		return
	}
	if userType != "specialist" && request.CreatorID != userID {
		logrus.Warn("DeleteRequestAPI: нет прав на удаление этой заявки: ", userType)
		h.writeJSONError(ctx, http.StatusForbidden, "Нет прав на удаление этой заявки")
		return
	}

	if err := h.Repository.DeleteRequest(requestID); err != nil {
		logrus.Warn("DeleteRequestAPI: ошибка удаления заявки ")
		h.writeJSONError(ctx, http.StatusInternalServerError, "Ошибка при удалении заявки")
		return
	}

	delkey, err := h.RedisClient.Del(ctx, key).Result()
	if err != nil {
		logrus.Error("ошибка удаления кэша:", err)
	} else {
		logrus.Infof("удалено ключей: %d", delkey)
	}
	delkeys, err := h.RedisClient.Del(ctx, keys).Result()
	if err != nil {
		logrus.Error("ошибка удаления кэша:", err)
	} else {
		logrus.Infof("удалено ключей: %d", delkeys)
	}

	ctx.JSON(http.StatusOK, gin.H{"status": "ok"})
}

// GetRequestFactsAPI godoc
// @Summary Получить факты заявки
// @Description Возвращает список фактов для заявки. Требуется авторизация.
// @Tags requests
// @Accept json
// @Produce json
// @Security ApiKeyAuth
// @Param id path int true "ID заявки"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]interface{}
// @Failure 401 {object} map[string]interface{}
// @Failure 404 {object} map[string]interface{}
// @Router /api/requests/{id}/facts [get]
func (h *Handler) GetRequestFactsAPI(ctx *gin.Context) {
	userID, err := h.getCurrentUserID(ctx)
	if err != nil {
		logrus.Warnf("GetRequestFactsAPI: требуется вход: %d", userID)
		h.writeJSONError(ctx, http.StatusUnauthorized, "Требуется вход")
		return
	}

	userType, err := h.getCurrentUserType(ctx)
	if err != nil {
		logrus.Errorf("GetRequestFactsAPI: ошибка при определении роли пользователя: %d", userID)
		h.writeJSONError(ctx, http.StatusInternalServerError, "Ошибка при определении роли пользователя")
		return
	}

	idStr := ctx.Param("id")
	requestID, err := strconv.Atoi(idStr)
	if err != nil {
		logrus.Errorf("GetRequestFactsAPI: неверный ID заявки: %d", requestID)
		h.writeJSONError(ctx, http.StatusBadRequest, "Неверный ID заявки")
		return
	}

	key := fmt.Sprintf(
		"requestfacts:%s:%s:%d",
		idStr,
		userType,
		userID,
	)

	cached, err := h.RedisClient.Get(ctx, key).Result()
	if err == nil {
		logrus.Debug("GetRequestFactsAPI: cache hit")

		var requests []repository.Request
		if err := json.Unmarshal([]byte(cached), &requests); err == nil {

			ctx.JSON(http.StatusOK, gin.H{
				"status":   "ok",
				"count":    len(requests),
				"requests": requests,
			})
			return
		}
	} else {
		logrus.Debugf("GetRequestFactsAPI: cache miss для key=%s", key)
	}

	request, err := h.Repository.GetRequestByID(requestID)
	if err != nil {
		logrus.Error("GetRequestFactsAPI: ошибка получения заявки ", err)
		h.writeJSONError(ctx, http.StatusInternalServerError, "Ошибка при получении заявки")
		return
	}
	if request == nil {
		logrus.Error("GetRequestFactsAPI: заявка не найдена: ", request)
		h.writeJSONError(ctx, http.StatusNotFound, "Заявка не найдена")
		return
	}
	if userType == "employee" && request.CreatorID != userID {
		logrus.Errorf("GetRequestFactsAPI: доступ к заявке %d запрещён для %d", requestID, userID)
		h.writeJSONError(ctx, http.StatusForbidden, "Доступ к этой заявке запрещён")
		return
	}

	facts, err := h.Repository.GetFactsByRequestID(requestID)
	if err != nil {
		logrus.Error("GetRequestFactsAPI: ошибка при получении фактов заявки")
		h.writeJSONError(ctx, http.StatusInternalServerError, "Ошибка при получении фактов заявки")
		return
	}

	data, err := json.Marshal(request)
	if err == nil {
		err = h.RedisClient.Set(
			ctx,
			key,
			data,
			120*time.Second,
		).Err()

		if err != nil {
			logrus.Warn("GetRequestFactsAPI: ошибка при установке кэша", err)
		}
	}

	ctx.JSON(http.StatusOK, gin.H{"status": "ok", "facts": facts})
}

// CreateFactAPI godoc
// @Summary Добавить факт к заявке
// @Description Создает новый факт для заявки. Требуется авторизация сотрудника и наличие скриншота.
// @Tags requests
// @Accept multipart/form-data
// @Produce json
// @Security ApiKeyAuth
// @Param id path int true "ID заявки"
// @Param title formData string true "Название факта"
// @Param description formData string true "Описание факта"
// @Param screenshot formData file true "Скриншот (изображение)"
// @Success 201 {object} map[string]interface{}
// @Failure 400 {object} map[string]interface{}
// @Failure 401 {object} map[string]interface{}
// @Failure 403 {object} map[string]interface{}
// @Router /api/requests/{id}/facts [post]
func (h *Handler) CreateFactAPI(ctx *gin.Context) {
	userID, err := h.getCurrentUserID(ctx)
	if err != nil {
		logrus.Error("CreateFactAPI: требуется авторизация:", err)
		h.writeJSONError(ctx, http.StatusUnauthorized, "Требуется авторизация")
		return
	}

	userType, err := h.getCurrentUserType(ctx)
	if err != nil || userType != "employee" {
		logrus.Error("CreateFactAPI: только сотрудник добавляет факты:", err)
		h.writeJSONError(ctx, http.StatusForbidden, "Только сотрудник может добавлять факты")
		return
	}

	idStr := ctx.Param("id")
	requestID, err := strconv.Atoi(idStr)
	if err != nil {
		logrus.Error("CreateFactAPI: неверный ID заявки:", err)
		h.writeJSONError(ctx, http.StatusBadRequest, "Неверный ID заявки")
		return
	}

	key := fmt.Sprintf(
		"request:%d:%s:%d",
		requestID,
		userType,
		userID,
	)

	keys := fmt.Sprintf(
		"requests:%s:%d",
		userType,
		userID,
	)

	request, err := h.Repository.GetRequestByID(requestID)
	if err != nil || request == nil {
		logrus.Error("CreateFactAPI: заявка не найдена:", err)
		h.writeJSONError(ctx, http.StatusNotFound, "Заявка не найдена")
		return
	}

	if request.CreatorID != userID {
		logrus.Warn("CreateFactAPI: только автор добавляет факты:", err)
		h.writeJSONError(ctx, http.StatusForbidden, "Только автор заявки может добавлять факты")
		return
	}

	title := strings.TrimSpace(ctx.PostForm("title"))
	description := strings.TrimSpace(ctx.PostForm("description"))

	if title == "" {
		logrus.Warn("CreateFactAPI: нету названия файла:", err)
		h.writeJSONError(ctx, http.StatusBadRequest, "Название факта обязательно")
		return
	}

	if description == "" {
		logrus.Warn("CreateFactAPI: нету описания факта:", err)
		h.writeJSONError(ctx, http.StatusBadRequest, "Описание факта обязательно")
		return
	}

	file, header, err := ctx.Request.FormFile("screenshot")
	if err != nil {
		logrus.Error("CreateFactAPI: ошибка при получении файла:", err)
		h.writeJSONError(ctx, http.StatusBadRequest, "Скриншот обязателен")
		return
	}
	defer func() {
		if err := file.Close(); err != nil {
			logrus.Error("CreateFactAPI: ошибка при закрытии файла:", err)
		}
	}()

	objectName := repository.GenerateObjectName(header.Filename)
	screenshotURL, err := h.Repository.MinIOClient.UploadFile(ctx.Request.Context(), file, header, objectName)
	if err != nil {
		logrus.Error("CreateFactAPI: ошибка при загрузке файла в MinIO:", err)
		h.writeJSONError(ctx, http.StatusInternalServerError, "Ошибка при загрузке файла")
		return
	}

	fact := &repository.Fact{
		RequestID:     requestID,
		Title:         title,
		Description:   description,
		ScreenshotURL: screenshotURL,
	}

	if err := h.Repository.CreateFact(fact); err != nil {
		logrus.Error("CreateFactAPI: ошибка при создании факта:", err)
		h.writeJSONError(ctx, http.StatusInternalServerError, "Ошибка при создании факта")
		return
	}

	delkey, err := h.RedisClient.Del(ctx, key).Result()
	if err != nil {
		logrus.Error("ошибка удаления кэша:", err)
	} else {
		logrus.Infof("удалено ключей: %d", delkey)
	}
	delkeys, err := h.RedisClient.Del(ctx, keys).Result()
	if err != nil {
		logrus.Error("ошибка удаления кэша:", err)
	} else {
		logrus.Infof("удалено ключей: %d", delkeys)
	}

	ctx.JSON(http.StatusCreated, gin.H{"status": "ok", "fact": fact})
}
