//go:build sqlite

package factory_test

import (
	"gosso/internal/database/factory"
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

func TestSQLiteDatabaseFactory(t *testing.T) {
	Convey("SQLite 数据库工厂测试", t, func() {

		Convey("创建 SQLite Dialector", func() {
			dbFactory := factory.NewDatabaseFactory()
			So(dbFactory, ShouldNotBeNil)

			dialector := dbFactory.CreateDialector("sqlite3", ":memory:")
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