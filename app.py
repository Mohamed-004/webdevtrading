from flask import Flask, render_template

app = Flask(__name__)
app.config['DEBUG'] = True

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/report-payout')
def report_payout():
    return render_template('report_payout.html')

@app.route('/featured-firms')
def featured_firms():
    return render_template('featured-firms.html')

@app.route('/terms-of-service')
def tos():
    return render_template('terms-of-service.html')

# @app.route('/reports/tft-10a')
# def tft_10():
#     return render_template('report_1_mock.html')

@app.route('/reports/dei-20a')
def dei_20a():
    return render_template('dei_case_20a.html')

@app.route('/reports/fast-forex-funding-30a')
def fff_30a():
    return render_template('fff_case_30a.html')

@app.route('/reports')
def report_preview():
    return render_template('report_section.html')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)