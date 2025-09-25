//go:build postgres

package factory_test

import (
	"gosso/internal/database/factory"
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

func TestPostgreSQLDatabaseFactory(t *testing.T) {
	Convey("PostgreSQL 数据库工厂测试", t, func() {

		Convey("创建 PostgreSQL Dialector", func() {
			dbFactory := factory.NewDatabaseFactory()
			So(dbFactory, ShouldNotBeNil)

			dialector := dbFactory.CreateDialector("postgres", "host=localhost user=test password=test dbname=test port=5432 sslmode=disable")
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
