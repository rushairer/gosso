import { createBrowserRouter } from 'react-router-dom'
import Home from '@/pages/Home'
import Profile from '@/pages/Profile'
import Authorize from '@/pages/oauth/Authorize'

const router = createBrowserRouter([
    {
        path: '/',
        element: <Home />,
    },
    {
        path: '/profile',
        element: <Profile />,
    },
    {
        path: '/oauth2/authorize',
        element: <Authorize />,
    },
])

export default router
