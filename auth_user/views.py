from rest_framework.response import Response
from rest_framework import status
from rest_framework.generics import GenericAPIView
from rest_framework import serializers
# Create your views here.

from django.contrib.auth.models import User
from .serializers import LoginSerializer, CustomTokenSerializer
from django.conf import settings

class LoginUserView(GenericAPIView):
   queryset = User.objects.all()
   serializer_class = LoginSerializer

   def post(self, request, *args, **kwargs):
      try:
         serializer = self.get_serializer(data=request.data)
         serializer.is_valid(raise_exception=True)

         email = serializer.validated_data.get('email')
         password = serializer.validated_data.get('password')

         user = User.objects.filter(email=email).first()

         ## Validamos si el usuario existe en la base de datos
         if user is None:
            raise serializers.ValidationError('No existe el usuario')
         
         ## Validamos la constraseña
         if not user.check_password(password):
            raise serializers.ValidationError('Contraseña invalida')

         ## Generamos un token con un serializador
         token = CustomTokenSerializer.get_token(user)

         response = Response({
            "message": "Login exitoso",
            "email": user.email,
            "data": {
               "refresh": str(token),
               "access": str(token.access_token),
            }
         }, status=status.HTTP_200_OK)

         # Establece el token en una cookie segura
         is_secure = not settings.DEBUG  # `True` en producción, `False` en desarrollo

         response.set_cookie(
            key="access_token",
            value=str(token.access_token),
            httponly=True,
            secure=is_secure, 
            samesite="Lax",
            max_age=3600
         )
         return response

         """
            key="access_token": Nombre de la cookie que almacena el token.
            value=access_token: El valor de la cookie es el token de acceso generado.
            httponly=True: Asegura que el token no sea accesible desde JavaScript, solo desde el servidor.
            secure=True: La cookie solo se enviará a través de HTTPS (actívalo en producción).
            samesite="Lax": Previene el envío de la cookie en solicitudes de terceros, protegiendo contra ataques CSRF.
            max_age=3600: Define el tiempo de expiración de la cookie en segundos (en este caso, 1 hora).
         """
      except serializers.ValidationError as e:
         return Response({
            "message": "Datos invalidos",
            "error": e.detail
         }, status=status.HTTP_400_BAD_REQUEST)
      
      except Exception as e:
         print(e)
         return Response({
            "message": "Ocurrio un error inesperado",
            "error": str(e)
         }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
      


# from rest_framework_simplejwt.tokens import AccessToken
# from rest_framework.exceptions import AuthenticationFailed
# class LogoutUserView(GenericAPIView):
#    serializer_class = CustomTokenSerializer


#    def get(self, request, *args, **kwargs):
   
#       try:
#          serializer = self.get_serializer(data=request.data)
#          serializer.is_valid(raise_exception=True)
         
         
#          # Decodifica y valida el token
#          access_token = AccessToken(token)
#          # Puedes acceder a los datos del usuario en `access_token['user_id']`, etc.
#          raise AuthenticationFailed("Token inválido o expirado")
         
#          return access_token
      

#       except serializers.ValidationError as e:
#          return Response({
#             "message": "Datos invalidos",
#             "error": e.detail
#          }, status=status.HTTP_400_BAD_REQUEST)
#       except AuthenticationFailed as e:
#          return Response({
#             "message": "Token inválido o expirado",
#          }, status=status.HTTP_401_UNAUTHORIZED)
#       except Exception as e:   
#          return Response({
#             "message": "Ocurrio un error inesperado",
#             "error": str(e)
#          }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# def validate_token(token):
#     try:
#         # Decodifica y valida el token
#         access_token = AccessToken(token)
#         # Puedes acceder a los datos del usuario en `access_token['user_id']`, etc.
#         return access_token
#     except Exception as e:
#         raise AuthenticationFailed("Token inválido o expirado")