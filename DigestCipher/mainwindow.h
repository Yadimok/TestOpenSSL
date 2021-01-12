/*
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */


#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QtWidgets>

#include "objectmessagedigest.h"
#include "common.h"


QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private:
    Ui::MainWindow *ui;
    MD_ALGO     mStateMdAlgo;
    QString     mAlgoName;

    ObjectMessageDigest *kObjectMD;

    QHBoxLayout *mMainBoxLayout;
    QTabWidget  *mTabWidget;

    QWidget         *mWidgetDigest;
    QWidget         *mWidgetCipher;

    QGroupBox       *mGroupBoxDigest;
    QRadioButton    *mRadioButtonMD4;
    QRadioButton    *mRadioButtonMD5;
    QRadioButton    *mRadioButtonRMD160;
    QRadioButton    *mRadiobuttonSha1;
    QRadioButton    *mRadiobuttonSha224;
    QRadioButton    *mRadiobuttonSha256;
    QRadioButton    *mRadiobuttonSha384;
    QRadioButton    *mRadiobuttonSha512;
    QRadioButton    *mRadiobuttonSha512_224;
    QRadioButton    *mRadiobuttonSha512_256;
    QRadioButton    *mRadiobuttonSha3_224;
    QRadioButton    *mRadiobuttonSha3_256;
    QRadioButton    *mRadiobuttonSha3_384;
    QRadioButton    *mRadiobuttonSha3_512;
    QRadioButton    *mRadiobuttonShake128;
    QRadioButton    *mRadiobuttonShake256;
    QRadioButton    *mRadiobuttonStreebog256;
    QRadioButton    *mRadiobuttonStreebog512;


    QPushButton     *mPushButtonChooseFile;
    QLabel          *mLabelHashResult;
    QLabel          *mLabelFileName;
    QLineEdit       *mLineEditResult;

private slots:
    void PushButtonChooseFile();
    void ReceiveHashResult(QByteArray barray);
    void PushRadioButtonClicked(int id);

};
#endif // MAINWINDOW_H
