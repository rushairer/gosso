import React from 'react'
import { Layout, Button, Typography, theme } from 'antd'
import { ReactComponent as LogoTitle } from '@/assets/images/logo_title.svg'
import { useEmotionCss } from '@ant-design/use-emotion-css'
import { SimpleContainerClassFunction } from '@/style'
import { useRequest } from 'ahooks'
import { getClient } from '@/services/api'
import { useSearchParams } from 'react-router-dom'

const { Text } = Typography
const { useToken } = theme

const Authorize: React.FC = () => {
    const { token } = useToken()

    const containerClassName = useEmotionCss(SimpleContainerClassFunction)

    const [searchParams] = useSearchParams()

    const { data, error, loading } = useRequest(getClient, {
        defaultParams: [searchParams.get('client_id') ?? ''],
    })

    const clientName = loading ? '' : error ? '' : data?.name

    return (
        <Layout>
            <div className={containerClassName}>
                <LogoTitle fill={token.colorText} height="40" />
                <Text>{clientName} 请求使用您的帐号授权。</Text>
                <form method="POST">
                    <Button type="primary" htmlType="submit" size="large" block>
                        授权
                    </Button>
                </form>
            </div>
        </Layout>
    )
}

export default Authorize
