from django.urls import path
from .views import (signup, login, logout,
                    get_products, get_product, create_product, edit_product, delete_product,
                    get_manufacturers, get_manufacturer, create_manufacturer, edit_manufacturer,
                    delete_manufacturer, CountryListView, CountryDetailView, OrderListView, OrderDetailView,
                    CartListView, CartDetailView)

urlpatterns = [
    path('signup/', signup, name='signup'),
    path('login/', login, name='login'),
    path('logout/', logout, name='logout'),
    path('get_products/', get_products, name='get_products'),
    path('get_product/', get_product, name='get_product'),
    path('create_product/', create_product, name='create_product'),
    path('edit_product/', edit_product, name='edit_product'),
    path('delete_product/', delete_product, name='delete_product'),
    path('get_manufacturers/', get_manufacturers, name='get_manufacturers'),
    path('get_manufacturer/', get_manufacturer, name='get_manufacturer'),
    path('create_manufacturer/', create_manufacturer, name='create_manufacturer'),
    path('edit_manufacturer/', edit_manufacturer, name='edit_manufacturer'),
    path('delete_manufacturer/', delete_manufacturer, name='delete_manufacturer'),
    path('country/', CountryListView.as_view(), name='country_list'),
    path('country/<int:pk>/', CountryDetailView.as_view(), name='country_detail'),
    path('order/', OrderListView.as_view(), name='order_list'),
    path('order/<int:pk>/', OrderDetailView.as_view(), name='order-detail'),
    path('cart/', CartListView.as_view(), name='cart'),
    path('cart/<int:pk>/', CartDetailView.as_view(), name='cart-detail')
]
