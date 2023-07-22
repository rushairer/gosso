import Webpack from 'webpack'
import type { CracoWebpackConfig } from '@craco/types'
import path from 'path'

export const webpack: CracoWebpackConfig = {
    alias: {
        '@': path.resolve(__dirname, 'src'),
    },
    plugins: {
        add: [
            new Webpack.LoaderOptionsPlugin({
                options: {
                    test: /\.svg(\?v=\d+\.\d+\.\d+)?$/,
                    use: [
                        {
                            loader: 'babel-loader',
                        },
                        {
                            loader: '@svgr/webpack',
                            options: {
                                babel: false,
                                icon: true,
                            },
                        },
                    ],
                },
            }),
        ],
    },
    configure: (webpackConfig, { env, paths }) => {
        if (paths && webpackConfig.output) {
            paths.appBuild = webpackConfig.output.path = path.resolve(
                '../web/resources/',
                'public'
            )
        }
        return webpackConfig
    },
}
