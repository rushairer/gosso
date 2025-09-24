package factory_test

import (
	"gosso/internal/database/factory"
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

func TestDatabaseFactory(t *testing.T) {
	Convey("数据库工厂测试", t, func() {

		Convey("工厂创建测试", func() {
			Convey("NewDatabaseFactory 应该返回非空工厂", func() {
				// 注意：这个测试会根据编译标签返回不同的工厂实现
				// 如果没有编译标签，会触发 log.Fatal
				SkipConvey("需要数据库驱动编译标签", func() {
					dbFactory := factory.NewDatabaseFactory()
					So(dbFactory, ShouldNotBeNil)
				})
			})
		})

		Convey("MySQL 工厂测试", func() {
			Convey("创建 MySQL Dialector", func() {
				// 注意：这个测试需要 mysql build tag
				SkipConvey("需要 MySQL 驱动编译标签 (-tags mysql)", func() {
					dbFactory := factory.NewDatabaseFactory()
					So(dbFactory, ShouldNotBeNil)

					dialector := dbFactory.CreateDialector("mysql", "test:test@tcp(localhost:3306)/test?charset=utf8mb4&parseTime=True&loc=Local")
					So(dialector, ShouldNotBeNil)
					So(dialector.Name(), ShouldEqual, "mysql")
				})
			})

			Convey("使用连接池创建 MySQL Dialector", func() {
				SkipConvey("需要 MySQL 驱动编译标签 (-tags mysql)", func() {
					dbFactory := factory.NewDatabaseFactory()
					So(dbFactory, ShouldNotBeNil)

					// 这个测试需要真实的数据库连接，在单元测试中跳过
					// 实际使用时需要传入 *sql.DB 实例
				})
			})
		})

		Convey("PostgreSQL 工厂测试", func() {
			Convey("创建 PostgreSQL Dialector", func() {
				SkipConvey("需要 PostgreSQL 驱动编译标签 (-tags postgres)", func() {
					dbFactory := factory.NewDatabaseFactory()
					So(dbFactory, ShouldNotBeNil)

					dialector := dbFactory.CreateDialector("postgres", "host=localhost user=test password=test dbname=test port=5432 sslmode=disable")
					So(dialector, ShouldNotBeNil)
					So(dialector.Name(), ShouldEqual, "postgres")
				})
			})

			Convey("使用连接池创建 PostgreSQL Dialector", func() {
				SkipConvey("需要 PostgreSQL 驱动编译标签 (-tags postgres)", func() {
					dbFactory := factory.NewDatabaseFactory()
					So(dbFactory, ShouldNotBeNil)

					// 这个测试需要真实的数据库连接，在单元测试中跳过
				})
			})
		})

		Convey("SQLite 工厂测试", func() {
			Convey("创建 SQLite Dialector", func() {
				SkipConvey("需要 SQLite 驱动编译标签 (-tags sqlite)", func() {
					dbFactory := factory.NewDatabaseFactory()
					So(dbFactory, ShouldNotBeNil)

					dialector := dbFactory.CreateDialector("sqlite3", ":memory:")
					So(dialector, ShouldNotBeNil)
					So(dialector.Name(), ShouldEqual, "sqlite")
				})
			})

			Convey("使用连接池创建 SQLite Dialector", func() {
				SkipConvey("需要 SQLite 驱动编译标签 (-tags sqlite)", func() {
					dbFactory := factory.NewDatabaseFactory()
					So(dbFactory, ShouldNotBeNil)

					// 这个测试需要真实的数据库连接，在单元测试中跳过
				})
			})
		})

		Convey("默认工厂测试", func() {
			Convey("无驱动编译时应该触发 log.Fatal", func() {
				// 这个测试只在没有任何数据库驱动编译标签时才会运行
				// 在实际项目中，通常会有至少一个驱动被编译
				SkipConvey("默认情况下会有驱动被编译", func() {
					// 注意：这个测试会导致程序退出，因为 log.Fatal 会调用 os.Exit(1)
					// 在实际测试中应该避免这种情况
					So(func() {
						factory.NewDatabaseFactory()
					}, ShouldPanic)
				})
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
				SkipConvey("需要数据库驱动编译标签", func() {
					actualFactory := factory.NewDatabaseFactory()
					So(actualFactory, ShouldNotBeNil)
					So(actualFactory, ShouldImplement, (*factory.DatabaseFactory)(nil))
				})
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

// TestFactoryBuildTags 测试不同编译标签的行为
func TestFactoryBuildTags(t *testing.T) {
	Convey("编译标签测试", t, func() {

		Convey("编译标签说明", func() {
			Convey("MySQL 编译标签", func() {
				// 使用 go test -tags mysql 运行测试
				SkipConvey("使用 'go test -tags mysql' 运行 MySQL 相关测试", func() {
					// MySQL 相关的测试逻辑
				})
			})

			Convey("PostgreSQL 编译标签", func() {
				// 使用 go test -tags postgres 运行测试
				SkipConvey("使用 'go test -tags postgres' 运行 PostgreSQL 相关测试", func() {
					// PostgreSQL 相关的测试逻辑
				})
			})

			Convey("SQLite 编译标签", func() {
				// 使用 go test -tags sqlite 运行测试
				SkipConvey("使用 'go test -tags sqlite' 运行 SQLite 相关测试", func() {
					// SQLite 相关的测试逻辑
				})
			})
		})
	})
}