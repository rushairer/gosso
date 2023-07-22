import React, { useEffect } from 'react'
import ReactDOM from 'react-dom/client'
import { ConfigProvider, theme } from 'antd'
import { RouterProvider } from 'react-router-dom'
import router from './router'
import 'antd/dist/reset.css'
import './index.css'

const root = ReactDOM.createRoot(document.getElementById('root') as HTMLElement)

const App: React.FC = () => {
    const [darkTheme, setDarkTheme] = React.useState<boolean>(
        window.matchMedia('(prefers-color-scheme: dark)').matches
    )

    useEffect(() => {
        let mediaQuery = window.matchMedia('(prefers-color-scheme: dark)')
        mediaQuery.addEventListener('change', refreshTheme)

        // this is the cleanup function to remove the listener
        return () => mediaQuery.removeEventListener('change', refreshTheme)
    }, [])

    const refreshTheme = () => {
        setDarkTheme(window.matchMedia('(prefers-color-scheme: dark)').matches)
    }

    return (
        <ConfigProvider
            theme={{
                algorithm: darkTheme
                    ? theme.darkAlgorithm
                    : theme.defaultAlgorithm,
            }}>
            <RouterProvider router={router} />
        </ConfigProvider>
    )
}

root.render(
    <React.StrictMode>
        <App />
    </React.StrictMode>
)
