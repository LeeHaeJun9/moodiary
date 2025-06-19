# emotion_analyzer.py
import pandas as pd
import re
from konlpy.tag import Okt

# 간단한 감성 사전 (KNU 감성사전 활용)
emotion_dict = {
    "기쁨": ["행복", "기쁘다", "좋다", "즐겁다", "감사", "웃다", "기쁨", "웃", "좋음", "ㅋㅋ"],
    "슬픔": ["우울", "슬프다", "눈물", "힘들다", "괴롭다", "슬픔", "괴로움", "ㅠㅠ", "힘듬"],
    "분노": ["화", "짜증", "불쾌", "속상"],
    "불안": ["불안", "걱정", "초조", "두렵다", "두려움"]
}

okt = Okt()

def analyze_emotion(text):
    tokens = okt.morphs(text, stem=True)
    scores = {emotion: 0 for emotion in emotion_dict}

    for token in tokens:
        for emotion, keywords in emotion_dict.items():
            if token in keywords:
                scores[emotion] += 1

    # 가장 높은 감정 1개 반환
    if max(scores.values()) == 0:
        return "중립"
    return max(scores, key=scores.get)