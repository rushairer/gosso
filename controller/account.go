package controller

import (
	"gosso/internal/service"

	"github.com/rushairer/gouno/task"

	accountTask "gosso/internal/task/account"
	"net/http"

	"github.com/gin-gonic/gin"
	gopipeline "github.com/rushairer/go-pipeline"
	"github.com/rushairer/gouno"
)

type AccountController struct {
	accountService *service.AccountService

	taskPipeline *gopipeline.Pipeline[task.Task]
}

type EmailRegisterRequest struct {
	Email string `json:"email" binding:"required,email"`
}

type PhoneRegisterRequest struct {
	Phone string `json:"phone" binding:"required"`
}

func NewAccountController(accountService *service.AccountService, taskPipeline *gopipeline.Pipeline[task.Task]) *AccountController {
	return &AccountController{
		accountService: accountService,
		taskPipeline:   taskPipeline,
	}
}

func (c *AccountController) EmailRegister(ctx *gin.Context) {
	var req EmailRegisterRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusOK, gouno.NewErrorResponse(http.StatusBadRequest, err.Error()))
		return
	}
	// TODO: 校验
	err := c.accountService.EmailRegister(ctx, req.Email)
	if err != nil {
		ctx.JSON(http.StatusOK, gouno.NewErrorResponse(http.StatusInternalServerError, err.Error()))
		return
	}
	c.taskPipeline.Add(ctx, accountTask.NewSendEmailCodeTask(req.Email))
	ctx.JSON(http.StatusOK, gouno.NewSuccessResponse(""))
}

func (c *AccountController) PhoneRegister(ctx *gin.Context) {
	var req PhoneRegisterRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusOK, gouno.NewErrorResponse(http.StatusBadRequest, err.Error()))
		return
	}
	// TODO: 校验
	err := c.accountService.PhoneRegister(ctx, req.Phone)
	if err != nil {
		ctx.JSON(http.StatusOK, gouno.NewErrorResponse(http.StatusInternalServerError, err.Error()))
		return
	}
	c.taskPipeline.Add(ctx, accountTask.NewSendPhoneCodeTask(req.Phone))
	ctx.JSON(http.StatusOK, gouno.NewSuccessResponse(""))
}
