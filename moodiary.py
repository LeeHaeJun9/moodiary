from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from flask import render_template, request, redirect, url_for, flash, jsonify, Flask
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from pytz import timezone
from emotion_analyzer import analyze_emotion
from sqlalchemy import func

# 기존 코드가 있다면 생략 가능
app = Flask(__name__, instance_relative_config=True)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SECRET_KEY'] = 'your-secret-key'  # 로그인 세션용

db = SQLAlchemy(app)

# ✅ 사용자 모델 정의
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(80), unique=True, nullable=False)  # 로그인용 ID
    name = db.Column(db.String(100), nullable=False)                 # 이름
    phone = db.Column(db.String(20), nullable=False)                 # 전화번호
    email = db.Column(db.String(120), unique=True, nullable=False)   # 이메일
    password = db.Column(db.String(200), nullable=False)             # 암호화된 비밀번호

class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone('Asia/Seoul')))

    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    author = db.relationship('User', backref=db.backref('posts', lazy=True))

    is_public = db.Column(db.Boolean, default=True) # 공개 여부

    emotion = db.Column(db.String(50), nullable=True)

class Like(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)

    user = db.relationship('User', backref='likes')
    post = db.relationship('Post', backref='likes')

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone('Asia/Seoul')))

    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)

    user = db.relationship('User', backref='comments')
    post = db.relationship('Post', backref='comments')

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@app.template_filter('format_kst')
def format_kst(value):
    try:
        return value.astimezone(timezone('Asia/Seoul')).strftime('%Y-%m-%d %H:%M')
    except Exception:
        return value  # 혹시나 None 등 오류 방지

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        user_id = request.form['user_id']
        name = request.form['name']
        phone = request.form['phone']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        # 비밀번호 확인
        if password != confirm_password:
            flash('비밀번호가 일치하지 않습니다.')
            return redirect(url_for('register'))

        # 아이디 또는 이메일 중복 확인
        if User.query.filter_by(user_id=user_id).first():
            flash('이미 존재하는 아이디입니다.')
            return redirect(url_for('register'))
        if User.query.filter_by(email=email).first():
            flash('이미 사용 중인 이메일입니다.')
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(password)
        new_user = User(
            user_id=user_id,
            name=name,
            phone=phone,
            email=email,
            password=hashed_password
        )
        db.session.add(new_user)
        db.session.commit()
        flash('회원가입이 완료되었습니다.')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user_id = request.form['user_id']
        password = request.form['password']

        user = User.query.filter_by(user_id=user_id).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            flash('로그인에 성공했습니다.')
            return redirect(url_for('index'))
        else:
            flash('아이디 또는 비밀번호가 잘못되었습니다.')
            return redirect(url_for('login'))
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('로그아웃 되었습니다.')
    return redirect(url_for('login'))

@app.route('/create', methods=['GET', 'POST'])
@login_required
def create_post():
    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        is_public = 'is_public' in request.form

        emotion = analyze_emotion(content)
        print("🎯 분석된 감정:", emotion)

        new_post = Post(title=title, content=content, is_public=is_public, author=current_user, emotion=emotion)
        db.session.add(new_post)
        db.session.commit()
        flash(f'감정이 분석되어 "{emotion}"으로 저장되었습니다.')
        return redirect(url_for('index'))
    return render_template('create_post.html')

@app.after_request
def add_header(response):
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

@app.route('/')
def index():
    page = request.args.get('page', 1, type=int)
    per_page = 5
    keyword = request.args.get('q', '', type=str).strip()

    query = Post.query.filter_by(is_public=True)

    if keyword:
        search = f"%{keyword}%"
        query = query.filter(Post.title.ilike(search) | Post.content.ilike(search))

    posts = query.order_by(Post.created_at.desc()).paginate(page=page, per_page=per_page)

    return render_template('index.html', posts=posts)
    

@app.route('/post/<int:post_id>', methods=['GET', 'POST'])
def post_detail(post_id):
    post= Post.query.get_or_404(post_id)

    # 비공개 글 보호 로직 (GET/POST 둘 다 적용)
    if not post.is_public and (not current_user.is_authenticated or post.author != current_user):
        flash('비공개 글입니다. 접근 권한이 없습니다.')
        return redirect(url_for('index'))
    
    # 댓글 페이징 처리
    page = request.args.get('page', 1, type=int)
    per_page = 3
    comments = Comment.query.filter_by(post_id=post.id).order_by(Comment.created_at.asc()).paginate(page=page, per_page=per_page)


    # 수정 폼 제출 처리
    if request.method == 'POST':
        if not current_user.is_authenticated or post.author != current_user:
            flash('수정 권한이 없습니다.')
            return redirect(url_for('post_detail', post_id=post.id))
        
        post.title = request.form['title']
        post.content = request.form['content']
        db.session.commit()
        flash('감정 기록이 수정되었습니다.')
        return redirect(url_for('post_detail', post_id=post.id))
    return render_template('post_detail.html', post=post, comments=comments)

@app.route('/post/<int:post_id>/delete', methods=['POST'])
@login_required
def delete_post(post_id):
    post = Post.query.get_or_404(post_id)
    if post.author != current_user:
        flash('삭제 권한이 없습니다.')
        return redirect(url_for('post_detail', post_id=post_id))

    db.session.delete(post)
    db.session.commit()
    flash('감정 기록이 삭제되었습니다.')
    return redirect(url_for('index'))

@app.route('/my')
@login_required
def my_posts():
    page = request.args.get('page', 1, type=int)
    per_page = 5
    posts = Post.query.filter_by(author=current_user)\
                      .order_by(Post.created_at.desc())\
                      .paginate(page=page, per_page=per_page)
    return render_template('my_posts.html', posts=posts)
    

@app.route('/my/edit', methods=['GET', 'POST'])
@login_required
def edit_profile():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        confirm = request.form['confirm_password']

        current_user.name = name
        current_user.email = email

        if password:
            if password != confirm:
                flash('비밀번호가 일치하지 않습니다.')
                return redirect(url_for('edit_profile'))
            current_user.password = generate_password_hash(password)

        db.session.commit()
        flash('회원 정보가 수정되었습니다.')
        return redirect(url_for('my_posts'))
    
    return render_template('edit_profile.html')

@app.route('/like/<int:post_id>', methods=['POST'])
@login_required
def like(post_id):
    post = Post.query.get_or_404(post_id)
    existing_like = Like.query.filter_by(user_id=current_user.id, post_id=post.id).first()

    if existing_like:
        db.session.delete(existing_like)
        db.session.commit()
        flash('공감을 취소했습니다.')
    else:
        new_like = Like(user=current_user, post=post)
        db.session.add(new_like)
        db.session.commit()
        flash('감정에 공감했습니다!')
    
    return redirect(url_for('post_detail', post_id=post.id))

@app.route('/comment/<int:post_id>', methods=['POST'])
@login_required
def add_comment(post_id):
    content = request.form['content']
    post = Post.query.get_or_404(post_id)

    new_comment = Comment(content=content, user=current_user, post=post)
    db.session.add(new_comment)
    db.session.commit()
    flash('댓글이 등록되었습니다.')
    return redirect(url_for('post_detail', post_id=post.id))

@app.route('/comment/<int:comment_id>/delete', methods=['POST'])
@login_required
def delete_comment(comment_id):
    comment = Comment.query.get_or_404(comment_id)
    if comment.user != current_user:
        flash('삭제 권한이 없습니다.')
        return redirect(url_for('post_detail', post_id=comment.post_id, page=request.args.get('page', 1)))
    
    post_id = comment.post_id
    db.session.delete(comment)
    db.session.commit()
    flash('댓글이 삭제되었습니다.')
    return redirect(url_for('post_detail', post_id=post_id))

@app.route('/comment/<int:comment_id>/edit', methods=['POST'])
@login_required
def edit_comment(comment_id):
    comment = Comment.query.get_or_404(comment_id)
    if comment.user != current_user:
        flash('수정 권한이 없습니다.')
        return redirect(url_for('post_detail', post_id=comment.post.id))
    
    comment.content = request.form['content']
    db.session.commit()
    flash('댓글이 수정되었습니다.')
    return redirect(url_for('post_detail', post_id=comment.post.id))

@app.route('/autocomplete')
def autocomplete():
    query = request.args.get('q', '').strip()

    if not query:
        return jsonify([])

    matches = Post.query.filter(Post.title.ilike(f'%{query}%')) \
                        .order_by(Post.created_at.desc()) \
                        .limit(5).all()

    suggestions = [post.title for post in matches]
    return jsonify(suggestions)

@app.context_processor
def inject_suggestions():
    return {
        'suggested_keywords': ['행복', '우울', '불안', '감사', '설렘', '지침']
    }

@app.route('/stats_data')
@login_required
def stats_data():

    results = db.session.query(
        func.strftime('%Y-%m-%d', Post.created_at).label('day'),
        Post.emotion,
        func.count(Post.id)
    ).filter(
        Post.user_id == current_user.id
    ).group_by(
        'day', Post.emotion
    ).order_by(
        'day'
    ).all()

    data = {}
    for day, emotion, count in results:
        if day not in data:
            data[day] = {}
        data[day][emotion] = count

    return jsonify(data)

@app.route('/stats')
@login_required
def stats():
    return render_template('stats.html')


# ✅ 실행
if __name__ == '__main__':
    app.run(debug=True)