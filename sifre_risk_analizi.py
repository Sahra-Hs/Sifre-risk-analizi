import streamlit as st
import numpy as np
import skfuzzy as fuzz
import skfuzzy.control as ctrl
import matplotlib.pyplot as plt


st.set_page_config(page_title="Siber Güvenlik Şifre Risk Analizi", layout="wide")


@st.cache_resource
def bulanik_sistem_kur():
    
    uzunluk = ctrl.Antecedent(np.arange(0, 21, 1), 'uzunluk')
    cesitlilik = ctrl.Antecedent(np.arange(0, 5, 1), 'cesitlilik')
    tahmin = ctrl.Antecedent(np.arange(0, 11, 1), 'tahmin') 
    risk = ctrl.Consequent(np.arange(0, 101, 1), 'risk')

    
    uzunluk['kisa'] = fuzz.trapmf(uzunluk.universe, [0, 0, 6, 10])
    uzunluk['orta'] = fuzz.trimf(uzunluk.universe, [8, 12, 14])
    uzunluk['uzun'] = fuzz.trapmf(uzunluk.universe, [12, 16, 20, 20])

    cesitlilik['az'] = fuzz.trimf(cesitlilik.universe, [0, 0, 2])
    cesitlilik['orta'] = fuzz.trimf(cesitlilik.universe, [1, 2, 3])
    cesitlilik['cok'] = fuzz.trimf(cesitlilik.universe, [2, 4, 4])

    tahmin['dusuk'] = fuzz.trimf(tahmin.universe, [0, 0, 4]) 
    tahmin['normal'] = fuzz.trimf(tahmin.universe, [3, 5, 7]) 
    tahmin['yuksek'] = fuzz.trimf(tahmin.universe, [6, 10, 10]) 

    risk['dusuk'] = fuzz.trapmf(risk.universe, [0, 0, 20, 40])
    risk['orta'] = fuzz.trimf(risk.universe, [30, 50, 70])
    risk['yuksek'] = fuzz.trapmf(risk.universe, [60, 80, 100, 100])

    
    kurallar = [
        ctrl.Rule(uzunluk['kisa'] & cesitlilik['az'] & tahmin['yuksek'], risk['yuksek']),
        ctrl.Rule(uzunluk['kisa'] & cesitlilik['az'] & tahmin['normal'], risk['yuksek']),
        ctrl.Rule(uzunluk['kisa'] & cesitlilik['az'] & tahmin['dusuk'], risk['yuksek']),
        ctrl.Rule(uzunluk['kisa'] & cesitlilik['orta'] & tahmin['yuksek'], risk['yuksek']),
        ctrl.Rule(uzunluk['kisa'] & cesitlilik['orta'] & tahmin['normal'], risk['orta']),
        ctrl.Rule(uzunluk['kisa'] & cesitlilik['orta'] & tahmin['dusuk'], risk['orta']),
        ctrl.Rule(uzunluk['kisa'] & cesitlilik['cok'] & tahmin['yuksek'], risk['orta']),
        ctrl.Rule(uzunluk['kisa'] & cesitlilik['cok'] & tahmin['normal'], risk['orta']),
        ctrl.Rule(uzunluk['kisa'] & cesitlilik['cok'] & tahmin['dusuk'], risk['orta']),
        
        ctrl.Rule(uzunluk['orta'] & cesitlilik['az'] & tahmin['yuksek'], risk['yuksek']),
        ctrl.Rule(uzunluk['orta'] & cesitlilik['az'] & tahmin['normal'], risk['yuksek']),
        ctrl.Rule(uzunluk['orta'] & cesitlilik['az'] & tahmin['dusuk'], risk['orta']),
        ctrl.Rule(uzunluk['orta'] & cesitlilik['orta'] & tahmin['yuksek'], risk['orta']),
        ctrl.Rule(uzunluk['orta'] & cesitlilik['orta'] & tahmin['normal'], risk['orta']),
        ctrl.Rule(uzunluk['orta'] & cesitlilik['orta'] & tahmin['dusuk'], risk['dusuk']),
        ctrl.Rule(uzunluk['orta'] & cesitlilik['cok'] & tahmin['yuksek'], risk['orta']),
        ctrl.Rule(uzunluk['orta'] & cesitlilik['cok'] & tahmin['normal'], risk['dusuk']),
        ctrl.Rule(uzunluk['orta'] & cesitlilik['cok'] & tahmin['dusuk'], risk['dusuk']),
        
        ctrl.Rule(uzunluk['uzun'] & cesitlilik['az'] & tahmin['yuksek'], risk['orta']),
        ctrl.Rule(uzunluk['uzun'] & cesitlilik['az'] & tahmin['normal'], risk['orta']),
        ctrl.Rule(uzunluk['uzun'] & cesitlilik['az'] & tahmin['dusuk'], risk['orta']),
        ctrl.Rule(uzunluk['uzun'] & cesitlilik['orta'] & tahmin['yuksek'], risk['orta']),
        ctrl.Rule(uzunluk['uzun'] & cesitlilik['orta'] & tahmin['normal'], risk['dusuk']),
        ctrl.Rule(uzunluk['uzun'] & cesitlilik['orta'] & tahmin['dusuk'], risk['dusuk']),
        ctrl.Rule(uzunluk['uzun'] & cesitlilik['cok'] & tahmin['yuksek'], risk['dusuk']),
        ctrl.Rule(uzunluk['uzun'] & cesitlilik['cok'] & tahmin['normal'], risk['dusuk']),
        ctrl.Rule(uzunluk['uzun'] & cesitlilik['cok'] & tahmin['dusuk'], risk['dusuk'])
    ]

    risk_kontrol = ctrl.ControlSystem(kurallar)
    return risk_kontrol, kurallar, uzunluk, cesitlilik, tahmin, risk

risk_kontrol, tum_kurallar, uzunluk_obj, cesitlilik_obj, tahmin_obj, risk_obj = bulanik_sistem_kur()
simulasyon = ctrl.ControlSystemSimulation(risk_kontrol)


st.title("🔒 Akıllı Şifre Güvenliği ve Risk Değerlendirme Sistemi")
st.markdown("Bulanık Mantık (Fuzzy Logic) Teorisi Kullanılarak Geliştirilmiş Dönem Projesi Uygulaması")


st.sidebar.header("📥 Şifre Girdileri")
test_sifre = st.sidebar.text_input("Analiz Edilecek Örnek Şifre Yazın:", "P@ss123")


if test_sifre:
    u_default = min(len(test_sifre), 20)
    c_default = sum([any(c.islower() for c in test_sifre), any(c.isupper() for c in test_sifre), any(c.isdigit() for c in test_sifre), any(not c.isalnum() for c in test_sifre)])
    yaygin_liste = ["123", "password", "admin", "qwerty", "sifre", "gs", "fb", "bjk"]
    t_default = 9 if any(x in test_sifre.lower() for x in yaygin_liste) else (5 if test_sifre.isalnum() else 2)
else:
    u_default, c_default, t_default = 8, 2, 5


input_uzunluk = st.sidebar.slider("1. Giriş: Şifre Karakter Uzunluğu", 0, 20, int(u_default))
input_cesitlilik = st.sidebar.slider("2. Giriş: Karakter Çeşitlilik Skoru (0-4)", 0, 4, int(c_default))
input_tahmin = st.sidebar.slider("3. Giriş: Tahmin Edilebilirlik Skoru (0-10)", 0, 10, int(t_default))


simulasyon.input['uzunluk'] = input_uzunluk
simulasyon.input['cesitlilik'] = input_cesitlilik
simulasyon.input['tahmin'] = input_tahmin


try:
    simulasyon.compute()
    risk_skoru = simulasyon.output['risk']
except:
    risk_skoru = 50.0  


if risk_skoru < 40:
    durum, renk = "GÜVENLİ ŞİFRE ✅", "green"
elif risk_skoru < 70:
    durum, renk = "ORTA RİSKLİ ŞİFRE ⚠️", "orange"
else:
    durum, renk = "YÜKSEK RİSKLİ ŞİFRE ❌", "red"


col1, col2 = st.columns([1, 1])

with col1:
    st.subheader("📊 Analiz ve Durulaştırma Sonucu")
    st.metric(label="Hesaplanan Nihai Risk Oranı", value=f"%{risk_skoru:.2f}")
    st.markdown(f"#### Sistem Değerlendirmesi: :{renk}[{durum}]")
    st.info(f"**💡 Güncel Giriş Değerleri:** Uzunluk: {input_uzunluk} | Çeşitlilik: {input_cesitlilik} | Tahmin: {input_tahmin}")

   
    st.markdown("**Nihai Çıktı Aktif Grafik Görünümü (Ağırlık Merkezi/Centroid):**")
    
    fig, ax = plt.subplots(figsize=(6, 3.8))
    x_risk = risk_obj.universe
    y_dusuk = risk_obj['dusuk'].mf
    y_orta = risk_obj['orta'].mf
    y_yuksek = risk_obj['yuksek'].mf
    
    
    ax.plot(x_risk, y_dusuk, 'g', linewidth=1.5, label='Düşük')
    ax.plot(x_risk, y_orta, 'b', linewidth=1.5, label='Orta')
    ax.plot(x_risk, y_yuksek, 'r', linewidth=1.5, label='Yüksek')
    
    
    ax.axvline(x=risk_skoru, color='black', linestyle='-', linewidth=2.5, label=f'Sonuç: %{risk_skoru:.1f}')
    
    
    try:
        
        active_mf = np.zeros_like(x_risk)
        if risk_skoru < 40:
            active_mf = np.fmin(fuzz.interp_membership(x_risk, y_dusuk, risk_skoru), y_dusuk)
        elif risk_skoru < 70:
            active_mf = np.fmin(fuzz.interp_membership(x_risk, y_orta, risk_skoru), y_orta)
        else:
            active_mf = np.fmin(fuzz.interp_membership(x_risk, y_yuksek, risk_skoru), y_yuksek)
        ax.fill_between(x_risk, active_mf, facecolor='Orange', alpha=0.4)
    except:
        pass

    ax.set_title("Nihai Risk Durulaştırma Çizimi")
    ax.set_xlabel("Risk Oranı (%)")
    ax.set_ylabel("Üyelik Derecesi")
    ax.legend(loc='upper right')
    ax.grid(True, linestyle='--', alpha=0.5)
    
    st.pyplot(fig)
    plt.close(fig)

with col2:
    st.subheader("📈 Giriş Değişkenleri Üyelik Grafikleri")
    
    secilen_grafik = st.selectbox("Görselleştirmek istediğiniz üyelik fonksiyonunu seçin:", 
                                  ["Uzunluk Kümeleri", "Çeşitlilik Kümeleri", "Tahmin Edilebilirlik Kümeleri"])
    
    fig_g, ax_g = plt.subplots(figsize=(6, 4.2))
    
  
    if secilen_grafik == "Uzunluk Kümeleri":
        x_val = uzunluk_obj.universe
        ax_g.plot(x_val, uzunluk_obj['kisa'].mf, 'r', label='Kısa')
        ax_g.plot(x_val, uzunluk_obj['orta'].mf, 'b', label='Orta')
        ax_g.plot(x_val, uzunluk_obj['uzun'].mf, 'g', label='Uzun')
        ax_g.axvline(x=input_uzunluk, color='black', linestyle='--', linewidth=2, label=f'Giriş: {input_uzunluk}')
        ax_g.set_xlabel("Karakter Uzunluğu")
        
    elif secilen_grafik == "Çeşitlilik Kümeleri":
        x_val = cesitlilik_obj.universe
        ax_g.plot(x_val, cesitlilik_obj['az'].mf, 'r', label='Az')
        ax_g.plot(x_val, cesitlilik_obj['orta'].mf, 'b', label='Orta')
        ax_g.plot(x_val, cesitlilik_obj['cok'].mf, 'g', label='Çok')
        ax_g.axvline(x=input_cesitlilik, color='black', linestyle='--', linewidth=2, label=f'Giriş: {input_cesitlilik}')
        ax_g.set_xlabel("Karakter Türü Çeşitliliği")
        
    else:
        x_val = tahmin_obj.universe
        ax_g.plot(x_val, tahmin_obj['dusuk'].mf, 'g', label='Düşük')
        ax_g.plot(x_val, tahmin_obj['normal'].mf, 'b', label='Normal')
        ax_g.plot(x_val, tahmin_obj['yuksek'].mf, 'r', label='Yüksek')
        ax_g.axvline(x=input_tahmin, color='black', linestyle='--', linewidth=2, label=f'Giriş: {input_tahmin}')
        ax_g.set_xlabel("Sözlük / Tahmin Edilebilirlik Derecesi")
        
    ax_g.set_title(secilen_grafik)
    ax_g.set_ylabel("Üyelik Derecesi")
    ax_g.legend(loc='upper right')
    ax_g.grid(True, linestyle='--', alpha=0.5)
    
    st.pyplot(fig_g)
    plt.close(fig_g)


st.markdown("---")
st.subheader("📜 Sistem Kural Tabanı ve Durumu (Toplam 27 Kural)")

kural_data = []
for i, kural in enumerate(tum_kurallar):
    kural_metni = str(kural).replace("IF", "").replace("AND", "VE").replace("THEN", "İSE")
    kural_data.append(f"**Kural {i+1}:** IF {kural_metni}")

with st.expander("Sistemdeki Tüm Kuralları Listele / Gizle"):
    for kd in kural_data:
        st.write(kd)