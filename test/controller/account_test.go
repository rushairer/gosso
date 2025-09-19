package controller_test

import (
	"context"
	"gosso/utility"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"
)

func TestAccountController_EmailRegister(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*2)
	defer cancel()
	engine := utility.NewTestEngine(ctx, true)
	w := httptest.NewRecorder()

	Convey("模拟请求/account/email", t, func() {
		req, _ := http.NewRequest(http.MethodPost, "/account/email", strings.NewReader(`{"address": "test@example.com"}`))
		req.Header.Set("Content-Type", "application/json")

		Convey("接口有返回", func() {
			engine.ServeHTTP(w, req)

			So(w.Code, ShouldEqual, http.StatusOK)
		})

		Convey("等待2秒后结束", func() {
			<-ctx.Done()
			So(true, ShouldBeTrue)
		})

	})
}

func TestAccountController_PhoneRegister(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*2)
	defer cancel()
	engine := utility.NewTestEngine(ctx, true)
	w := httptest.NewRecorder()

	Convey("模拟请求/account/email", t, func() {
		req, _ := http.NewRequest(http.MethodPost, "/account/phone", strings.NewReader(`{"number": "12345678901"}`))
		req.Header.Set("Content-Type", "application/json")

		Convey("接口有返回", func() {
			engine.ServeHTTP(w, req)

			So(w.Code, ShouldEqual, http.StatusOK)
		})

		Convey("等待2秒后结束", func() {
			<-ctx.Done()
			So(true, ShouldBeTrue)
		})

	})
}
