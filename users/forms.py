from django import forms
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from django.contrib.auth import get_user_model, authenticate
from django.utils.html import strip_tags
from django.core.validators import RegexValidator

User = get_user_model()

class CustomUserCreationForm(UserCreationForm): 
    email = forms.EmailField(required=True, max_length=60,widget=forms.EmailInput(attrs={"class": "input-register from-control", "placeholder": "Your email" }))
    first_name = forms.CharField(required=True, max_length=30, widget=forms.TextInput(attrs={"class": "input-register from-control", "placeholder": "Your first name" }))
    last_name = forms.CharField(required=True, max_length=30, widget=forms.TextInput(attrs={"class": "input-register from-control", "placeholder": "Your last name" }))
    password1 = forms.CharField(required=True, widget=forms.PasswordInput(attrs={"class": "input-register from-control", "placeholder": "Your password" }))
    password2 = forms.CharField(required=True, widget=forms.PasswordInput(attrs={"class": "input-register from-control", "placeholder": "Confirm your password" }))
    marketing_consent1=forms.BooleanField(required=False, initial=False, label="I agree to receive marketing emails", widget=forms.CheckboxInput(attrs={"class": "input-register from-control"}))
    marketing_consent2=forms.BooleanField(required=False, initial=False, label="I agree to receive personalized commercial communications.", widget=forms.CheckboxInput(attrs={"class": "input-register from-control"}))  

    class Meta:
        model= User
        fields=('first_name', 'last_name', 'email', 'password1', 'password2', 'marketing_consent1', 'marketing_consent2')


    def clean_email(self):
        email=self.cleanned_data.get('email')
        if User.objects.filter(email=email).exists():
            raise forms.ValidationError("Email already exists")
        return email


    def save(self, commit=True):
        user = super().save(commit=False)
        user.username=None
        user.marketin_connsent1 = self.cleanned_data('marketing_consent1')
        user.marketin_connsent2 = self.cleanned_data('marketing_consent2')
        if commit:
            user.save()
            return user
    
class CustomUserLoginForm(AuthenticationForm):
    username = forms.CharField(label="Email", widget=forms.TextInput(attrs={"AutoFocus":True, 'class': 'input-register form-control', 'placeholder': 'Your email' }))
    password=forms.CharField(label="Password", widget=forms.PasswordInput(attrs={"class": "input-register form-control", "placeholder": "Your password" }))

    def clean(self):
        email=self.cleanned_data.get('username') 
        password=self.cleanned_data.get('password')

        if email and password:
            self.user_cache= authenticate(self.request, email=email, password=password)
            if self.user_cache is None:
                raise forms.ValidationError('invalid email or password.')
            elif not self.user_cache.is_active:
                raise forms.ValidationError('This account is inactive.')
        return self.cleaned_data
    
class CustomUserUpdateForm(forms.ModelForm):
    phone = forms.CharField(required=False, validators=[RegexValidator(r'^\+?1?\d{9,15}$', 'Phone number must be entered in the format: "+999999999". Up to 15 digits allowed.')], widget=forms.TextInput(attrs={"class": "input-register from-control", "placeholder": "Your phone number" }))
    first_name= forms.CharField(required=True, max_length=30, widget=forms.TextInput(attrs={"class": "input-register from-control", "placeholder": "Your first name" }))
    last_name= forms.CharField(required=True, max_length=30, widget=forms.TextInput(attrs={"class": "input-register from-control", "placeholder": "Your last name" }))
    email= forms.EmailField(required=False, max_length=60, widget=forms.EmailInput(attrs={"class": "input-register from-control", "placeholder": "Your email" }))
    

    class Meta:
        model = User
        fields = ('first_name', 'last_name', 'email', 'address1', 'address2', 'city', 'country', 'province', 'postal_code', 'phone')
        widgets={
            'email': forms.EmailInput(attrs={"class": "input-register from-control", "placeholder": "Your email" }),
            'first_name': forms.TextInput(attrs={"class": "input-register from-control", "placeholder": "Your first name" }),
            'last_name': forms.TextInput(attrs={"class": "input-register from-control", "placeholder": "Your last name" }),
            'address1': forms.TextInput(attrs={"class": "input-register from-control", "placeholder": "Your address 1" }),
            'address2': forms.TextInput(attrs={"class": "input-register from-control", "placeholder": "Your address 2" }),
            'city': forms.TextInput(attrs={"class": "input-register from-control", "placeholder": "Your city" }),
            'country': forms.TextInput(attrs={"class": "input-register from-control", "placeholder": "Your country" }),
            'province': forms.TextInput(attrs={"class": "input-register from-control", "placeholder": "Your province" }),
            'postal_code': forms.TextInput(attrs={"class": "input-register from-control", "placeholder": "Your postal code" }),

        }

    def clean_email(self):
        email= self.cleaned_data.get('email')
        if email and User.objects.filter(email=email).exclude(id=self.instance.id).exists():
            raise forms.ValidationError("Email already exists")
        return email
    
    def clean(self):
        cleaned_data = super().clean()
        if not cleaned_data.get('email'):
            cleaned_data['email'] = self.instance.email 

            for field in ['address1', 'address2', 'city', 'country', 'province', 'postal_code']:
                if cleaned_data.get(field):
                    cleaned_data[field] = strip_tags(cleaned_data.get(field))
                return cleaned_data
                