//go:build sqlite

package factory_test

import (
	"gosso/internal/database/factory"
	"gosso/utility"
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

func TestSQLiteDatabaseFactory(t *testing.T) {
	Convey("SQLite 数据库工厂测试", t, func() {

		Convey("创建 SQLite Dialector", func() {
			// 使用 utility 辅助方法获取 SQLite 配置
			driver, dsn, _ := utility.GetTestSQLiteConfig()
			So(driver, ShouldNotBeEmpty)
			So(dsn, ShouldNotBeEmpty)

			dbFactory := factory.NewDatabaseFactory()
			So(dbFactory, ShouldNotBeNil)

			// 使用配置文件中的 SQLite 连接字符串
			dialector := dbFactory.CreateDialector(driver, dsn)
			So(dialector, ShouldNotBeNil)
			So(dialector.Name(), ShouldEqual, "sqlite")
		})

		Convey("使用 utility 辅助方法创建 SQLite Dialector", func() {
			// 直接使用 utility 提供的 Dialector
			dialector := utility.GetTestSQLiteDialector()
			So(dialector, ShouldNotBeNil)
			So(dialector.Name(), ShouldEqual, "sqlite")
		})

		Convey("使用连接池创建 SQLite Dialector", func() {
			dbFactory := factory.NewDatabaseFactory()
			So(dbFactory, ShouldNotBeNil)

			// 这个测试需要真实的数据库连接，在单元测试中跳过
			SkipConvey("需要真实的数据库连接", func() {
				// SQLite 连接池测试逻辑
			})
		})
	})
}
