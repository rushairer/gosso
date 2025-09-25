//go:build postgres

package factory_test

import (
	"gosso/internal/database/factory"
	"gosso/utility"
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

func TestPostgreSQLDatabaseFactory(t *testing.T) {
	Convey("PostgreSQL 数据库工厂测试", t, func() {

		Convey("创建 PostgreSQL Dialector", func() {
			// 使用 utility 辅助方法获取 PostgreSQL 配置
			driver, dsn, _ := utility.GetTestPostgreSQLConfig()
			So(driver, ShouldNotBeEmpty)
			So(dsn, ShouldNotBeEmpty)

			dbFactory := factory.NewDatabaseFactory()
			So(dbFactory, ShouldNotBeNil)

			// 使用配置文件中的 PostgreSQL 连接字符串
			dialector := dbFactory.CreateDialector(driver, dsn)
			So(dialector, ShouldNotBeNil)
			So(dialector.Name(), ShouldEqual, "postgres")
		})

		Convey("使用 utility 辅助方法创建 PostgreSQL Dialector", func() {
			// 直接使用 utility 提供的 Dialector
			dialector := utility.GetTestPostgreSQLDialector()
			So(dialector, ShouldNotBeNil)
			So(dialector.Name(), ShouldEqual, "postgres")
		})

		Convey("使用连接池创建 PostgreSQL Dialector", func() {
			dbFactory := factory.NewDatabaseFactory()
			So(dbFactory, ShouldNotBeNil)

			// 这个测试需要真实的数据库连接，在单元测试中跳过
			SkipConvey("需要真实的数据库连接", func() {
				// PostgreSQL 连接池测试逻辑
			})
		})
	})
}
