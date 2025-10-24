package controller

import (
	"net/http"

	"github.com/rushairer/gouno/task"

	"gosso/internal/common/service/account"
	accountTask "gosso/internal/common/task/account"

	"github.com/gin-gonic/gin"
	gopipeline "github.com/rushairer/go-pipeline/v2"
	"github.com/rushairer/gouno"
)

type AccountController struct {
	accountService *account.AccountService

	taskPipeline *gopipeline.StandardPipeline[task.Task]
}

type EmailRegisterRequest struct {
	Address string `json:"address" binding:"required,email"`
}

type PhoneRegisterRequest struct {
	Number string `json:"number" binding:"required"`
}

func NewAccountController(accountService *account.AccountService, taskPipeline *gopipeline.StandardPipeline[task.Task]) *AccountController {
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
	err := c.accountService.EmailRegister(ctx, req.Address)
	if err != nil {
		ctx.JSON(http.StatusOK, gouno.NewErrorResponse(http.StatusInternalServerError, err.Error()))
		return
	}
	dataChan := c.taskPipeline.DataChan()
	dataChan <- accountTask.NewSendEmailCodeTask(req.Address)
	ctx.JSON(http.StatusOK, gouno.NewSuccessResponse(""))
}

func (c *AccountController) PhoneRegister(ctx *gin.Context) {
	var req PhoneRegisterRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusOK, gouno.NewErrorResponse(http.StatusBadRequest, err.Error()))
		return
	}
	// TODO: 校验
	err := c.accountService.PhoneRegister(ctx, req.Number)
	if err != nil {
		ctx.JSON(http.StatusOK, gouno.NewErrorResponse(http.StatusInternalServerError, err.Error()))
		return
	}
	dataChan := c.taskPipeline.DataChan()
	dataChan <- accountTask.NewSendPhoneCodeTask(req.Number)
	ctx.JSON(http.StatusOK, gouno.NewSuccessResponse(""))
}
