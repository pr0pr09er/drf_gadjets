from django.contrib import admin
from .models import Cart, Country, Product, Manufacturer, Order

# Register your models here.
admin.site.register(Cart)
admin.site.register(Product)
admin.site.register(Manufacturer)
admin.site.register(Order)
admin.site.register(Country)
