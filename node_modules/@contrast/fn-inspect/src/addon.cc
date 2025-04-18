#include <nan.h>

void FuncInfo(const v8::FunctionCallbackInfo<v8::Value> &info) {
    if (info.Length() < 1 || !info[0]->IsFunction()) {
        info.GetReturnValue().Set(Nan::Null());
        return;
    }
    v8::Local<v8::Object> obj = Nan::New<v8::Object>();
    v8::Local<v8::Function> fn = info[0].As<v8::Function>();

    v8::Local<v8::Value> resourceName = fn->GetScriptOrigin().ResourceName();
    if (!resourceName.IsEmpty()) {
        Nan::Set(obj, Nan::New("file").ToLocalChecked(), resourceName);
        Nan::Set(obj, Nan::New("lineNumber").ToLocalChecked(), Nan::New(fn->GetScriptLineNumber()));
        Nan::Set(obj, Nan::New("method").ToLocalChecked(), fn->GetName());
        Nan::Set(obj, Nan::New("column").ToLocalChecked(), Nan::New(fn->GetScriptColumnNumber()));
    }

    info.GetReturnValue().Set(obj);
}

NODE_MODULE_INIT(/*exports, module, context*/) {
    v8::Isolate* isolate = context->GetIsolate();

    exports->Set(context,
        Nan::New("funcInfo").ToLocalChecked(),
        v8::FunctionTemplate::New(isolate, FuncInfo)->GetFunction(context).ToLocalChecked()
    );
}
