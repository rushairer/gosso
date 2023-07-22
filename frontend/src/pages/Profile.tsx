import React, { useEffect } from 'react'
import { Layout, Descriptions, Spin, Button } from 'antd'
import { useEmotionCss } from '@ant-design/use-emotion-css'
import { ProfileContainerClassFunction } from '@/style'
import { useRequest } from 'ahooks'
import { getViewer } from '@/services/api'

const Profile: React.FC = () => {
    const containerClassName = useEmotionCss(ProfileContainerClassFunction)

    const { data, error, loading } = useRequest(getViewer)

    const loadingHTML = <Spin />

    useEffect(
        () => {
            if (error !== undefined) {
                window.location.href = '/authentication/signout'
            }
        },
        // eslint-disable-next-line react-hooks/exhaustive-deps
        [error]
    )

    const profileHTML = error ? (
        <Spin />
    ) : (
        <>
            <Descriptions title="个人信息" column={1}>
                <Descriptions.Item label="用户名">
                    {data?.name}
                </Descriptions.Item>
                <Descriptions.Item label="邮箱">
                    {data?.email}
                </Descriptions.Item>
            </Descriptions>
            <Button
                danger
                onClick={() => {
                    window.location.href = '/authentication/signout'
                }}
                block>
                退出登录
            </Button>
        </>
    )

    return (
        <Layout>
            <div className={containerClassName}>
                {loading ? loadingHTML : profileHTML}
            </div>
        </Layout>
    )
}

export default Profile
