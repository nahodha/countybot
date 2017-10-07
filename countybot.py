from flask import Flask, render_template, request, url_for
from flask_bootstrap import Bootstrap
from flask_script import Manager


app = Flask(__name__)
bootstrap = Bootstrap(app)
manager = Manager(app)


@app.route('/')
def hello_world():
    return render_template('index.html')


@app.route('/ussd-pay', methods=['GET', 'POST'])
def ussd_endpoint():
    if request.method == 'POST':
        text = request.args['text']
        phonenumber = request.args['phonenumber']

        if text == '':
            response = 'CON Welcome to CountyBot how may we help you\n'
            response += '1. Register'
            response += '2. Make Payment'
            response += '3. Change Location'

        elif text == '1':
            response = 'CON Enter your name'

        elif text == '2':
            response == 'CON Enter amount payment'

        elif text == '3':
            response == 'CON Enter your new locaion.\n Additional charges will be incurred.'
        else:
            response = 'END goodbye'

        return response



if __name__ == '__main__':
    manager.run()
