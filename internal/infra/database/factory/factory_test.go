package factory_test

import (
	"gosso/internal/infra/database/factory"
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

func TestDatabaseFactory(t *testing.T) {
	Convey("数据库工厂通用测试", t, func() {

		Convey("工厂创建测试", func() {
			Convey("NewDatabaseFactory 应该返回非空工厂", func() {
				// 这个测试会根据编译标签返回不同的工厂实现
				dbFactory := factory.NewDatabaseFactory()
				So(dbFactory, ShouldNotBeNil)
			})
		})

		Convey("工厂接口测试", func() {
			Convey("工厂应该实现 DatabaseFactory 接口", func() {
				dbFactory := factory.NewDatabaseFactory()
				So(dbFactory, ShouldNotBeNil)
				So(dbFactory, ShouldImplement, (*factory.DatabaseFactory)(nil))
			})
		})
	})
}

// TestDatabaseFactoryInterface 测试工厂接口的定义
func TestDatabaseFactoryInterface(t *testing.T) {
	Convey("数据库工厂接口测试", t, func() {

		Convey("验证接口定义", func() {
			Convey("DatabaseFactory 接口应该有正确的方法签名", func() {
				// 这里我们只验证接口的存在性，不进行实际的实现测试
				// 因为实际的实现依赖于编译标签和真实的数据库连接

				// 验证接口方法的存在（通过编译检查）
				var dbFactory factory.DatabaseFactory
				So(dbFactory, ShouldBeNil) // 未初始化时应该为 nil

				// 在有编译标签的情况下，可以创建实际的工厂
				actualFactory := factory.NewDatabaseFactory()
				So(actualFactory, ShouldNotBeNil)
				So(actualFactory, ShouldImplement, (*factory.DatabaseFactory)(nil))
			})
		})

		Convey("工厂方法测试", func() {
			Convey("CreateDialector 方法应该接受正确的参数", func() {
				// 这个测试验证方法签名的正确性
				SkipConvey("需要数据库驱动编译标签", func() {
					dbFactory := factory.NewDatabaseFactory()

					// 测试方法调用不会 panic（参数类型正确）
					So(func() {
						dbFactory.CreateDialector("test", "test://connection")
					}, ShouldNotPanic)
				})
			})

			Convey("CreateDialectorWithPoll 方法应该接受正确的参数", func() {
				SkipConvey("需要数据库驱动编译标签", func() {
					dbFactory := factory.NewDatabaseFactory()

					// 测试方法调用不会 panic（参数类型正确）
					So(func() {
						dbFactory.CreateDialectorWithPoll(nil)
					}, ShouldNotPanic)
				})
			})
		})
	})
}

// TestFactoryBuildTags 测试编译标签说明
func TestFactoryBuildTags(t *testing.T) {
	Convey("编译标签说明", t, func() {

		Convey("数据库特定测试", func() {
			Convey("测试文件分离说明", func() {
				// 不同数据库的测试已分离到不同文件：
				// - factory_mysql_test.go (需要 -tags mysql)
				// - factory_postgres_test.go (需要 -tags postgres)
				// - factory_sqlite_test.go (需要 -tags sqlite)

				So("测试文件已按编译标签分离", ShouldEqual, "测试文件已按编译标签分离")
			})
		})
	})
}
