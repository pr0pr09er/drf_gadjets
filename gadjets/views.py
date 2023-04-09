from rest_framework import status
from django.contrib.auth.models import User
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework.permissions import IsAdminUser, IsAuthenticated
from rest_framework.views import APIView

from .models import Product, Manufacturer, Order, Cart, Country
from .serializers import (ProductSerializer, ManufacturerSerializer,
                          OrderSerializer, CartSerializer, CountrySerializer,
                          RegistrationSerializer)
from rest_framework.authtoken.models import Token


@api_view(['POST'])
def signup(request):
    serializer = RegistrationSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    user = serializer.save()
    token, created = Token.objects.get_or_create(user=user)
    return Response({'token': token.key}, status=status.HTTP_201_CREATED)


@api_view(['POST'])
def login(request):
    username = request.data.get('username')
    password = request.data.get('password')
    try:
        user = User.objects.get(username=username)
    except User.DoesNotExist:
        return Response(
            {
                'error': 'Invalid username'
            },
            status=status.HTTP_422_UNPROCESSABLE_ENTITY
        )
    if not user.check_password(password):
        return Response(
            {
                'error': 'Invalid password'
            },
            status=status.HTTP_401_UNAUTHORIZED
        )
    token, created = Token.objects.get_or_create(user=user)
    return Response(
        {
            'token': token.key
        }
    )


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def logout(request):
    try:
        request.user.auth_token.delete()
    except:
        return Response({
            "error": "logout failed"
        })
    return Response({'success': 'Logged out successfully.'}, status=status.HTTP_200_OK)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_products(request):
    queryset = Product.objects.all()
    serializer = ProductSerializer(queryset, many=True)

    return Response({"data": serializer.data}, status=status.HTTP_200_OK)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_product(request, pk):
    try:
        queryset = Product.objects.get(id=pk)
    except Product.DoesNotExist:
        return Response({"error": "Object does not exist"}, status=status.HTTP_404_NOT_FOUND)

    serializer = ProductSerializer(queryset)

    return Response({"data": serializer.data}, status=status.HTTP_200_OK)


@api_view(['POST'])
@permission_classes([IsAdminUser])
def create_product(request):
    serializer = ProductSerializer(data=request.data)

    serializer.is_valid(raise_exception=True)
    serializer.save()

    return Response({"data": serializer.data}, status=status.HTTP_201_CREATED)


@api_view(['PUT', 'PATCH'])
@permission_classes([IsAdminUser])
def edit_product(request, pk):
    try:
        queryset = Product.objects.get(id=pk)
    except Product.DoesNotExist:
        return Response({"error": "Object does not exist"}, status=status.HTTP_404_NOT_FOUND)

    serializer = ProductSerializer(data=request.data, instance=queryset)

    return Response({"data": serializer.data}, status=status.HTTP_201_CREATED)


@api_view(['DELETE'])
def delete_product(request, pk):
    try:
        queryset = Product.objects.get(id=pk)
    except Product.DoesNotExist:
        return Response({"error": "Object does not exist"}, status=status.HTTP_404_NOT_FOUND)

    queryset.delete()

    return Response({"object": "deleted"}, status=status.HTTP_201_CREATED)


@api_view(['GET'])
def get_manufacturers(request):
    queryset = Manufacturer.objects.all()
    serializer = ManufacturerSerializer(queryset, many=True)

    return Response({"data": serializer.data}, status=status.HTTP_200_OK)


@api_view(['GET'])
def get_manufacturer(request, pk):
    try:
        queryset = Manufacturer.objects.get(id=pk)
    except Manufacturer.DoesNotExist:
        return Response({"error": "Object does not exist"}, status=status.HTTP_404_NOT_FOUND)
    serializer = ManufacturerSerializer(queryset)

    return Response({"data": serializer.data}, status=status.HTTP_200_OK)


@api_view(['POST'])
@permission_classes([IsAdminUser])
def create_manufacturer(request):
    serializer = ManufacturerSerializer(data=request.data)

    serializer.is_valid(raise_exception=True)
    serializer.save()

    return Response({"data": serializer.data}, status=status.HTTP_201_CREATED)


@api_view(['PUT', 'PATCH'])
@permission_classes([IsAdminUser])
def edit_manufacturer(request, pk):
    try:
        queryset = Manufacturer.objects.get(id=pk)
    except Manufacturer.DoesNotExist:
        return Response({"error": "Object does not exist"}, status=status.HTTP_404_NOT_FOUND)

    serializer = ManufacturerSerializer(data=request.data, instance=queryset)

    return Response({"data": serializer.data}, status=status.HTTP_201_CREATED)


@api_view(['DELETE'])
@permission_classes([IsAdminUser])
def delete_manufacturer(request, pk):
    try:
        queryset = Manufacturer.objects.get(id=pk)
    except Manufacturer.DoesNotExist:
        return Response({"error": "Object does not exist"}, status=status.HTTP_404_NOT_FOUND)

    queryset.delete()

    return Response({"object": "deleted"}, status=status.HTTP_201_CREATED)


class CountryListView(APIView):
    permission_classes = (IsAdminUser,)

    def get(self, request):
        serializer = CountrySerializer(Country.objects.all(), many=True)

        return Response({
            "data": serializer.data
        }, status=200)

    def post(self, request):
        serializer = CountrySerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()

        return Response({
            "data": serializer.data
        }, status=201)


class CountryDetailView(APIView):
    permission_classes = (IsAdminUser,)

    def get(self, request, pk):
        try:
            obj = Country.objects.get(id=pk)
        except Country.DoesNotExist:
            return Response({
                "error": "Object does not exist"
            }, status=404)

        serializer = CountrySerializer(obj)

        return Response({"data": serializer.data}, status=200)

    def put(self, request, pk):
        try:
            obj = Country.objects.get(id=pk)
        except Country.DoesNotExist:
            return Response({
                "error": "Object does not exist"
            }, status=404)

        serializer = CountrySerializer(data=request.data, instance=obj)

        serializer.is_valid(raise_exception=True)
        serializer.save()

        return Response({"data": serializer.data}, status=201)

    def patch(self, request, pk):
        try:
            obj = Country.objects.get(id=pk)
        except Country.DoesNotExist:
            return Response({
                "error": "Object does not exist"
            }, status=404)

        serializer = CountrySerializer(data=request.data, instance=obj)

        serializer.is_valid(raise_exception=True)
        serializer.save()

        return Response({"data": serializer.data}, status=201)

    def delete(self, request, pk):
        try:
            obj = Country.objects.get(id=pk)
        except Country.DoesNotExist:
            return Response({
                "error": "Object does not exist"
            }, status=404)

        obj.delete()

        return Response({"data": "deleted"}, status=200)


class OrderListView(APIView):
    permission_classes = (IsAuthenticated,)

    def get(self, request):
        queryset = Order.objects.filter(user=request.user)

        serializer = OrderSerializer(queryset, many=True)

        return Response({"data": serializer.data}, status=status.HTTP_200_OK)

    def post(self, request):
        serializer = OrderSerializer(data=request.data)

        serializer.is_valid(raise_exception=True)
        serializer.save()

        return Response({"data": serializer.data}, status=status.HTTP_200_OK)


class OrderDetailView(APIView):
    permission_classes = (IsAuthenticated, )

    def get(self, request, pk):
        try:
            order = Order.objects.get(id=pk)
        except Order.DoesNotExist:
            return Response({"error": "Object does not exist"}, status=status.HTTP_404_NOT_FOUND)

        serializer = OrderSerializer(order)

        return Response({"data": serializer.data}, status=status.HTTP_200_OK)

    def put(self, request, pk):
        try:
            order = Order.objects.get(id=pk)
        except Order.DoesNotExist:
            return Response({"error": "Object does not exist"}, status=status.HTTP_404_NOT_FOUND)

        serializer = OrderSerializer(data=request.data, instance=order)

        serializer.is_valid(raise_exception=True)
        serializer.save()

        return Response({"data": serializer.data}, status=status.HTTP_201_CREATED)

    def patch(self, request, pk):
        try:
            order = Order.objects.get(id=pk)
        except Order.DoesNotExist:
            return Response({"error": "Object does not exist"}, status=status.HTTP_404_NOT_FOUND)

        serializer = OrderSerializer(data=request.data, instance=order)

        serializer.is_valid(raise_exception=True)
        serializer.save()

        return Response({"data": serializer.data}, status=status.HTTP_201_CREATED)

    def delete(self, request, pk):
        try:
            order = Order.objects.get(id=pk)
        except Order.DoesNotExist:
            return Response({"error": "Object does not exist"}, status=status.HTTP_404_NOT_FOUND)

        order.delete()

        return Response({"data": "no data"}, status=status.HTTP_204_NO_CONTENT)


class CartListView(APIView):
    @permission_classes([IsAdminUser])
    def get(self, request):
        queryset = Cart.objects.filter(user=request.user)

        serializer = CartSerializer(queryset, many=True)

        return Response({"data": serializer.data}, status=status.HTTP_200_OK)

    @permission_classes([IsAuthenticated])
    def post(self, request):
        serializer = CartSerializer(data=request.data)

        serializer.is_valid(raise_exception=True)
        serializer.save()

        return Response({"data": serializer.data}, status=status.HTTP_200_OK)


class CartDetailView(APIView):
    permission_classes = (IsAuthenticated,)

    def get(self, request, pk):
        try:
            cart = Cart.objects.get(id=pk)
        except Cart.DoesNotExist:
            return Response({"error": "Object does not exist"}, status=status.HTTP_404_NOT_FOUND)

        serializer = CartSerializer(cart)

        return Response({"data": serializer.data}, status=status.HTTP_200_OK)

    def put(self, request, pk):
        try:
            cart = Cart.objects.get(id=pk)
        except Cart.DoesNotExist:
            return Response({"error": "Object does not exist"}, status=status.HTTP_404_NOT_FOUND)

        serializer = CartSerializer(data=request.data, instance=cart)

        serializer.is_valid(raise_exception=True)
        serializer.save()

        return Response({"data": serializer.data}, status=status.HTTP_201_CREATED)

    def patch(self, request, pk):
        try:
            cart = Cart.objects.get(id=pk)
        except Cart.DoesNotExist:
            return Response({"error": "Object does not exist"}, status=status.HTTP_404_NOT_FOUND)

        serializer = CartSerializer(data=request.data, instance=cart)

        serializer.is_valid(raise_exception=True)
        serializer.save()

        return Response({"data": serializer.data}, status=status.HTTP_201_CREATED)

    def delete(self, request, pk):
        try:
            cart = Cart.objects.get(id=pk)
        except Cart.DoesNotExist:
            return Response({"error": "Object does not exist"}, status=status.HTTP_404_NOT_FOUND)

        cart.delete()

        return Response({"data": "no data"}, status=status.HTTP_204_NO_CONTENT)
