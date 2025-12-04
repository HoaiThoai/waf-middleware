from setuptools import setup, find_packages

setup(
    name="waf-middleware",           # Tên thư viện (khi pip install)
    version="1.0.0",                 # Phiên bản
    author="Nguyen Hoai Thoai",      # Tên tác giả
    author_email="hoaithoai35@gmail.com", # Email tác giả
    description="A powerful WAF Middleware for Flask with SQLi, XSS, and Logic protection",
    long_description=open("README.md", encoding="utf-8").read() if os.path.exists("README.md") else "",
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/waf-middleware", # Link github (nếu có, để tạm cũng được)
    packages=find_packages(),        # Tự động tìm thư mục waf_middleware
    include_package_data=True,       # Cho phép kèm file json, txt
    install_requires=[               # Các thư viện phụ thuộc bắt buộc phải có
        "Flask>=2.0.0",
        "requests>=2.25.0",
    ],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.6',
)