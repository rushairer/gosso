//go:build mysql

package factory_test

import (
	"gosso/internal/database/factory"
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

func TestMySQLDatabaseFactory(t *testing.T) {
	Convey("MySQL 数据库工厂测试", t, func() {

		Convey("创建 MySQL Dialector", func() {
			dbFactory := factory.NewDatabaseFactory()
			So(dbFactory, ShouldNotBeNil)

			dialector := dbFactory.CreateDialector("mysql", "test:test@tcp(localhost:3306)/test?charset=utf8mb4&parseTime=True&loc=Local")
			So(dialector, ShouldNotBeNil)
			So(dialector.Name(), ShouldEqual, "mysql")
		})

		Convey("使用连接池创建 MySQL Dialector", func() {
			dbFactory := factory.NewDatabaseFactory()
			So(dbFactory, ShouldNotBeNil)

			// 这个测试需要真实的数据库连接，在单元测试中跳过
			// 实际使用时需要传入 *sql.DB 实例
			SkipConvey("需要真实的数据库连接", func() {
				// MySQL 连接池测试逻辑
			})
		})
	})
}
