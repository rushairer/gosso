import React from 'react'
import { Layout, Button, Typography, ConfigProvider, theme } from 'antd'
import { useEmotionCss } from '@ant-design/use-emotion-css'

import { ReactComponent as LogoTitle } from '@/assets/images/logo_title.svg'
import { ReactComponent as IconApple } from '@/assets/images/icon_apple.svg'
import { ReactComponent as IconGithub } from '@/assets/images/icon_github.svg'
import { ReactComponent as IconWechat } from '@/assets/images/icon_wechat.svg'
import MetamaskButton from '@/components/MetamaskButton'
import { SimpleContainerClassFunction } from '@/style'
const { Text } = Typography
const { useToken } = theme

const Home: React.FC = () => {
    const { token } = useToken()

    const containerClassName = useEmotionCss(SimpleContainerClassFunction)

    return (
        <Layout>
            <div className={containerClassName}>
                <LogoTitle fill={token.colorText} height="40" />
                <Text>使用第三方帐号快速登录</Text>
                <ConfigProvider
                    theme={{
                        token: {
                            colorPrimary: '#00b96b',
                            colorText: '#FFFFFF',
                        },
                    }}>
                    <Button
                        type="primary"
                        size="large"
                        onClick={() => {
                            window.location.href = '/socials/wechat'
                        }}
                        block>
                        <IconWechat fill="#FFFFFF" />
                        <Text>通过 微信 登录</Text>
                    </Button>
                </ConfigProvider>
                <ConfigProvider
                    theme={{
                        token: {
                            colorPrimary: '#FFFFFF',
                            colorText: '#000000',
                        },
                    }}>
                    <Button
                        type="primary"
                        size="large"
                        onClick={() => {
                            window.location.href = '/socials/apple'
                        }}
                        block>
                        <IconApple fill="#000000" />
                        <Text>通过 Apple 登录</Text>
                    </Button>
                </ConfigProvider>
                <ConfigProvider
                    theme={{
                        token: {
                            colorPrimary: '#333333',
                            colorText: '#FFFFFF',
                        },
                    }}>
                    <Button
                        type="primary"
                        size="large"
                        onClick={() => {
                            window.location.href = '/socials/github'
                        }}
                        block>
                        <IconGithub fill="#FFFFFF" />
                        <Text>通过 Github 登录</Text>
                    </Button>
                </ConfigProvider>
                <ConfigProvider
                    theme={{
                        token: {
                            colorPrimary: '#222222',
                            colorText: '#FFFFFF',
                        },
                    }}>
                    <MetamaskButton />
                </ConfigProvider>
            </div>
        </Layout>
    )
}

export default Home
