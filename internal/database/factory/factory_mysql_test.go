//go:build mysql

package factory_test

import (
	"gosso/internal/database/factory"
	"gosso/utility"
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

func TestMySQLDatabaseFactory(t *testing.T) {
	Convey("MySQL 数据库工厂测试", t, func() {

		Convey("创建 MySQL Dialector", func() {
			// 使用 utility 辅助方法获取 MySQL 配置
			driver, dsn, _ := utility.GetTestMySQLConfig()
			So(driver, ShouldNotBeEmpty)
			So(dsn, ShouldNotBeEmpty)

			dbFactory := factory.NewDatabaseFactory()
			So(dbFactory, ShouldNotBeNil)

			// 使用配置文件中的 MySQL 连接字符串
			dialector := dbFactory.CreateDialector(driver, dsn)
			So(dialector, ShouldNotBeNil)
			So(dialector.Name(), ShouldEqual, "mysql")
		})

		Convey("使用 utility 辅助方法创建 MySQL Dialector", func() {
			// 直接使用 utility 提供的 Dialector
			dialector := utility.GetTestMySQLDialector()
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
